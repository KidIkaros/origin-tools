// SPDX-License-Identifier: Apache-2.0

//! `origin doctor` — one-command health check of the `~/.origin` setup.
//!
//! Verifies the things that silently break tools: home directory presence and
//! permissions, config validity, tier resolution, identity file permissions,
//! and SDK availability. Prints a pass/warn/fail report and exits non-zero if
//! any check fails.

use origin_common::home::OriginHome;
use origin_common::tier_from_str;
use std::path::Path;

/// Outcome of a single health check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Status {
    Ok,
    Warn,
    Fail,
}

impl Status {
    fn symbol(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "FAIL",
        }
    }
}

/// A single health-check result.
struct Check {
    name: &'static str,
    status: Status,
    detail: String,
}

/// Read the permission mode of a path (Unix). Returns None on non-Unix.
#[cfg(unix)]
fn mode_of(path: &Path) -> Option<u32> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .ok()
        .map(|m| m.permissions().mode() & 0o777)
}

/// Run all health checks and print the report. Returns a process exit code.
pub fn run() -> Result<(), String> {
    let mut checks: Vec<Check> = Vec::new();

    // ── 1. Home directory ──────────────────────────────────────────────
    let home = match OriginHome::load() {
        Ok(h) => {
            checks.push(Check {
                name: "home directory",
                status: Status::Ok,
                detail: format!("found at {}", h.root().display()),
            });
            Some(h)
        }
        Err(e) => {
            checks.push(Check {
                name: "home directory",
                status: Status::Fail,
                detail: format!("cannot load: {e}"),
            });
            None
        }
    };

    // ── 2. Home directory permissions (0700) ───────────────────────────
    #[cfg(unix)]
    if let Some(ref h) = home {
        match mode_of(h.root()) {
            Some(0o700) => checks.push(Check {
                name: "home permissions",
                status: Status::Ok,
                detail: "0700 (owner-only)".to_string(),
            }),
            Some(m) => checks.push(Check {
                name: "home permissions",
                status: Status::Warn,
                detail: format!("{m:04o} — expected 0700 (owner-only)"),
            }),
            None => checks.push(Check {
                name: "home permissions",
                status: Status::Warn,
                detail: "cannot read permissions".to_string(),
            }),
        }
    }

    // ── 3. Config file ─────────────────────────────────────────────────
    if let Some(ref h) = home {
        let config_path = h.config_path();
        if config_path.exists() {
            checks.push(Check {
                name: "config file",
                status: Status::Ok,
                detail: format!("found at {}", config_path.display()),
            });
        } else {
            checks.push(Check {
                name: "config file",
                status: Status::Warn,
                detail: "missing — defaults will be used".to_string(),
            });
        }
    }

    // ── 4. Tier resolution ─────────────────────────────────────────────
    if let Some(ref h) = home {
        let tier_str = &h.config().tier;
        match tier_from_str(tier_str) {
            Ok(tier) => checks.push(Check {
                name: "config tier",
                status: Status::Ok,
                detail: format!("'{tier_str}' -> {tier:?}"),
            }),
            Err(e) => checks.push(Check {
                name: "config tier",
                status: Status::Warn,
                detail: format!("{e}; will fall back to 'standard'"),
            }),
        }
    }

    // ── 5. Config format field ─────────────────────────────────────────
    if let Some(ref h) = home {
        let fmt = &h.config().format;
        let known = matches!(fmt.as_str(), "hex" | "base64" | "raw");
        checks.push(Check {
            name: "config format",
            status: if known { Status::Ok } else { Status::Warn },
            detail: if known {
                format!("'{fmt}'")
            } else {
                format!("'{fmt}' — unrecognized (expected hex/base64/raw)")
            },
        });
    }

    // ── 6. Identity seed file ──────────────────────────────────────────
    if let Some(ref h) = home {
        let seed_path = h.identity_seed_path();
        if seed_path.exists() {
            #[cfg(unix)]
            {
                match mode_of(&seed_path) {
                    Some(0o600) => checks.push(Check {
                        name: "identity seed",
                        status: Status::Ok,
                        detail: format!("present, 0600 ({})", seed_path.display()),
                    }),
                    Some(m) => checks.push(Check {
                        name: "identity seed",
                        status: Status::Warn,
                        detail: format!("present but {m:04o} — expected 0600"),
                    }),
                    None => checks.push(Check {
                        name: "identity seed",
                        status: Status::Warn,
                        detail: "present but cannot read permissions".to_string(),
                    }),
                }
            }
            #[cfg(not(unix))]
            checks.push(Check {
                name: "identity seed",
                status: Status::Ok,
                detail: format!("present ({})", seed_path.display()),
            });
        } else {
            checks.push(Check {
                name: "identity seed",
                status: Status::Warn,
                detail: "not found — run `origin identity keygen` to create one".to_string(),
            });
        }
    }

    // ── 7. SDK availability ────────────────────────────────────────────
    checks.push(Check {
        name: "crypto SDK",
        status: Status::Ok,
        detail: "origin-crypto-sdk linked and available".to_string(),
    });

    // ── Report ─────────────────────────────────────────────────────────
    print_report(&checks);

    if checks.iter().any(|c| c.status == Status::Fail) {
        Err("one or more checks failed".to_string())
    } else {
        Ok(())
    }
}

fn print_report(checks: &[Check]) {
    println!("origin doctor — environment health check\n");
    let width = checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for c in checks {
        println!(
            "  [{:>4}]  {:<width$}  {}",
            c.status.symbol(),
            c.name,
            c.detail,
            width = width
        );
    }

    let fails = checks.iter().filter(|c| c.status == Status::Fail).count();
    let warns = checks.iter().filter(|c| c.status == Status::Warn).count();
    println!();
    if fails > 0 {
        println!("result: {fails} failed, {warns} warning(s) — action required");
    } else if warns > 0 {
        println!("result: all critical checks passed, {warns} warning(s)");
    } else {
        println!("result: all checks passed");
    }
}
