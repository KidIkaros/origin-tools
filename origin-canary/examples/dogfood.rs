// SPDX-License-Identifier: Apache-2.0

//! Dogfood: origin-canary as a library.
//!
//! Creates a small source tree, embeds canary tokens with the variable +
//! watermark strategies, verifies the embedded distribution, then tampers
//! with a file and confirms the integrity check flags it.

use std::process::ExitCode;

use origin_canary::embed::{run_embed, EmbedConfig};
use origin_canary::verify::{verify_integrity, verify_source, IntegrityStatus};

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let base = std::env::temp_dir().join(format!(
        "origin-canary-dogfood-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&base);
    std::fs::create_dir_all(&base).unwrap();
    base
}

fn seed_tree(dir: &std::path::Path) {
    let src = dir.join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(
        src.join("app.py"),
        "# demo module\ndef handler():\n    return \"ok\"\n",
    )
    .unwrap();
    std::fs::write(
        src.join("config.js"),
        "// demo config\nexport const retries = 3;\n",
    )
    .unwrap();
}

fn main() -> ExitCode {
    let tree = tmpdir("tree");

    seed_tree(&tree);

    let cfg = EmbedConfig {
        source_dir: tree.clone(),
        project_id: 4242,
        distribution_id: "v1.3.0".to_string(),
        salt: "deadbeefcafebabe".to_string(),
        num_canaries: 4,
        manifest_out: None,
        strategy_names: vec![
            "variable.python".to_string(),
            "variable.javascript".to_string(),
            "watermark".to_string(),
        ],
    };

    let result = match run_embed(cfg) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("embed: {e}");
            return ExitCode::FAILURE;
        }
    };
    println!(
        "embed: {} token(s) into {} file(s); merkle_root={}",
        result.manifest.token_count,
        result.modified_files.len(),
        result.manifest.merkle_root.as_deref().unwrap_or("(none)")
    );

    // The untouched distribution verifies intact and all tokens are found.
    match verify_integrity(&tree, &result.manifest) {
        Ok(IntegrityStatus::Intact) => println!("integrity: intact"),
        other => {
            eprintln!("integrity: expected Intact, got {other:?}");
            return ExitCode::FAILURE;
        }
    }
    let matches = verify_source(&tree, &result.manifest);
    println!(
        "verify: {} of {} canaries located",
        matches.len(),
        result.manifest.len()
    );
    if matches.len() != result.manifest.len() {
        eprintln!("verify: expected all canaries to be found");
        return ExitCode::FAILURE;
    }

    // Tamper with a file: the tree hash changes and integrity flips.
    let app = tree.join("src/app.py");
    let original = std::fs::read_to_string(&app).unwrap();
    std::fs::write(&app, format!("{original}# attacker added a line\n")).unwrap();
    match verify_integrity(&tree, &result.manifest) {
        Ok(IntegrityStatus::Tampered) => println!("integrity: tampering detected"),
        other => {
            eprintln!("integrity: expected Tampered, got {other:?}");
            return ExitCode::FAILURE;
        }
    }

    println!("canary: OK");
    ExitCode::SUCCESS
}
