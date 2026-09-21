// SPDX-License-Identifier: Apache-2.0

//! Command implementations for origin-provenance.

use std::path::Path;

use crate::cli::{
    AppendArgs, AttestArgs, CheckArgs, Commands, CreateArgs, ScanArgs, StampArgs, UnwatermarkArgs,
    VerifyArgs, WatermarkArgs,
};
use crate::encoding::Action;
use crate::identity::Signer;
use crate::manifest::{FileStatus, Manifest};
use crate::opm::{self, Opm};
use crate::stamp::Stamp;
use crate::watermark::Watermark;

pub fn dispatch(cli: crate::cli::Cli) -> Result<(), String> {
    match cli.command {
        Commands::Stamp(args) => cmd_stamp(args),
        Commands::Verify(args) => cmd_verify(args),
        Commands::Watermark(args) => cmd_watermark(args),
        Commands::Unwatermark(args) => cmd_unwatermark(args),
        Commands::Scan(args) => cmd_scan(args),
        Commands::Check(args) => cmd_check(args),
        Commands::Create(args) => cmd_create(args),
        Commands::Append(args) => cmd_append(args),
        Commands::Attest(args) => cmd_attest(args),
    }
}

fn cmd_stamp(args: StampArgs) -> Result<(), String> {
    let path = Path::new(&args.file);
    if !path.exists() {
        return Err(format!("file not found: {}", args.file));
    }

    let stamp = Stamp::from_file(path).map_err(|e| format!("stamp: {e}"))?;
    let json = stamp.to_json().map_err(|e| format!("serialize: {e}"))?;

    let out_path = args
        .output
        .unwrap_or_else(|| format!("{}.stamp.json", args.file));
    std::fs::write(&out_path, &json).map_err(|e| format!("write {out_path}: {e}"))?;

    println!("Stamped: {}", args.file);
    println!("  hash:      {}", stamp.content_hash);
    println!("  size:      {} bytes", stamp.size);
    println!("  timestamp: {}", stamp.timestamp);
    println!("  saved to:  {out_path}");
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<(), String> {
    let file_path = Path::new(&args.file);
    let stamp_path = Path::new(&args.stamp);

    if !file_path.exists() {
        return Err(format!("file not found: {}", args.file));
    }
    if !stamp_path.exists() {
        return Err(format!("stamp not found: {}", args.stamp));
    }

    let stamp_json = std::fs::read_to_string(stamp_path).map_err(|e| format!("read stamp: {e}"))?;
    let stamp = Stamp::from_json(&stamp_json).map_err(|e| format!("parse stamp: {e}"))?;
    let content = std::fs::read(file_path).map_err(|e| format!("read file: {e}"))?;

    if stamp.verify_content(&content) {
        println!("✓ {} matches stamp", args.file);
        println!("  hash: {}", stamp.content_hash);
        Ok(())
    } else {
        let actual_hash = hex::encode(origin_crypto_sdk::sha3_256(&content));
        eprintln!("✗ {} does NOT match stamp", args.file);
        eprintln!("  expected: {}", stamp.content_hash);
        eprintln!("  actual:   {actual_hash}");
        Err("verification failed".into())
    }
}

fn cmd_watermark(args: WatermarkArgs) -> Result<(), String> {
    let path = Path::new(&args.file);
    if !path.exists() {
        return Err(format!("file not found: {}", args.file));
    }

    let content = std::fs::read(path).map_err(|e| format!("read: {e}"))?;

    if Watermark::has_watermark(&content) {
        return Err(format!("{} already contains a watermark", args.file));
    }

    let wm = Watermark::new(&content, args.label);
    let watermarked = wm.embed(&content).map_err(|e| format!("embed: {e}"))?;

    let out_path = args.output.unwrap_or_else(|| args.file.clone());
    std::fs::write(&out_path, &watermarked).map_err(|e| format!("write {out_path}: {e}"))?;

    println!("Watermarked: {} → {out_path}", args.file);
    println!("  original hash: {}", wm.content_hash);
    println!("  original size: {} bytes", wm.size);
    Ok(())
}

fn cmd_unwatermark(args: UnwatermarkArgs) -> Result<(), String> {
    let path = Path::new(&args.file);
    if !path.exists() {
        return Err(format!("file not found: {}", args.file));
    }

    let data = std::fs::read(path).map_err(|e| format!("read: {e}"))?;

    if !Watermark::has_watermark(&data) {
        return Err(format!("{} does not contain a watermark", args.file));
    }

    let (wm, original) = Watermark::extract(&data).map_err(|e| format!("extract: {e}"))?;

    println!("Watermark found in: {}", args.file);
    println!("  content hash: {}", wm.content_hash);
    println!("  original size: {} bytes", wm.size);
    println!("  timestamp:     {}", wm.timestamp);
    if let Some(label) = &wm.label {
        println!("  label:         {label}");
    }
    println!(
        "  integrity:     {}",
        if wm.verify(&original) {
            "✓ valid"
        } else {
            "✗ TAMPERED"
        }
    );

    if let Some(strip_path) = args.strip {
        std::fs::write(&strip_path, &original).map_err(|e| format!("write {strip_path}: {e}"))?;
        println!("  stripped to:   {strip_path}");
    }

    Ok(())
}

fn cmd_scan(args: ScanArgs) -> Result<(), String> {
    let dir = Path::new(&args.dir);
    if !dir.is_dir() {
        return Err(format!("not a directory: {}", args.dir));
    }

    let manifest = Manifest::scan(dir).map_err(|e| format!("scan: {e}"))?;
    let out_path = args
        .output
        .unwrap_or_else(|| format!("{}/provenance-manifest.json", args.dir));

    manifest
        .save(Path::new(&out_path))
        .map_err(|e| format!("save: {e}"))?;

    println!("Scanned: {}", args.dir);
    println!("  files:  {}", manifest.entries.len());
    println!("  saved:  {out_path}");
    Ok(())
}

fn cmd_check(args: CheckArgs) -> Result<(), String> {
    let dir = Path::new(&args.dir);
    let manifest_path = Path::new(&args.manifest);

    if !dir.is_dir() {
        return Err(format!("not a directory: {}", args.dir));
    }
    if !manifest_path.exists() {
        return Err(format!("manifest not found: {}", args.manifest));
    }

    let manifest = Manifest::load(manifest_path).map_err(|e| format!("load: {e}"))?;
    let results = manifest.verify(dir).map_err(|e| format!("verify: {e}"))?;
    let (ok, modified, missing, added) = Manifest::summarize(&results);

    println!("Verification: {}", args.dir);
    println!("  ✓ ok:       {ok}");
    if modified > 0 {
        println!("  ✗ modified: {modified}");
        for (path, status) in &results {
            if *status == FileStatus::Modified {
                println!("    - {path}");
            }
        }
    }
    if missing > 0 {
        println!("  ✗ missing:  {missing}");
        for (path, status) in &results {
            if *status == FileStatus::Missing {
                println!("    - {path}");
            }
        }
    }
    if added > 0 {
        println!("  + added:    {added}");
        for (path, status) in &results {
            if *status == FileStatus::Added {
                println!("    - {path}");
            }
        }
    }

    if modified > 0 || missing > 0 {
        Err("integrity check failed".into())
    } else {
        Ok(())
    }
}

/// Load a 32-byte signer seed: 32 raw bytes or 64-char hex. The seed is
/// consumed in-memory only — never printed, logged, or left in argv.
fn load_signer_seed(path: &str) -> Result<[u8; 32], String> {
    let raw = std::fs::read(path).map_err(|e| format!("read seed file {path}: {e}"))?;
    let raw_len = raw.len();
    if raw_len == 32 {
        return Ok(raw.try_into().expect("32 bytes"));
    }
    if raw_len == 64 {
        let text = String::from_utf8(raw).map_err(|_| "seed hex is not UTF-8".to_string())?;
        let bytes = hex::decode(text.trim()).map_err(|e| format!("bad seed hex: {e}"))?;
        if bytes.len() == 32 {
            return Ok(bytes.try_into().expect("32 bytes"));
        }
    }
    Err(format!(
        "seed file {path}: expected 32 raw bytes or 64-char hex, got {raw_len} bytes"
    ))
}

fn parse_action(s: &str) -> Result<Action, String> {
    match s {
        "capture" => Ok(Action::Capture),
        "edit" => Ok(Action::Edit),
        "publish" => Ok(Action::Publish),
        "annotate" => Ok(Action::Annotate),
        other => Err(format!(
            "unknown action '{other}' (expected capture|edit|publish|annotate)"
        )),
    }
}

fn cmd_create(args: CreateArgs) -> Result<(), String> {
    let asset = Path::new(&args.asset);
    if !asset.exists() {
        return Err(format!("file not found: {}", args.asset));
    }
    let action = parse_action(&args.action)?;
    let seed = load_signer_seed(&args.seed_file)?;
    let signer = Signer::from_seed(&seed).map_err(|e| format!("signer: {e}"))?;
    let chunk_size = args
        .chunk_size
        .unwrap_or(crate::encoding::DEFAULT_CHUNK_SIZE);

    let opm =
        Opm::create(asset, &signer, action, chunk_size).map_err(|e| format!("create: {e}"))?;

    let sidecar = args
        .sidecar
        .unwrap_or_else(|| opm::sidecar_path(asset).to_string_lossy().into_owned());
    opm::save(&opm, Path::new(&sidecar)).map_err(|e| format!("save {sidecar}: {e}"))?;

    println!("Manifest created: {sidecar}");
    println!("  asset_id:  {}", opm.asset_id);
    println!("  action:    {}", args.action);
    println!("  signer:    {}", signer.fingerprint_hex());
    Ok(())
}

fn cmd_append(args: AppendArgs) -> Result<(), String> {
    let asset = Path::new(&args.asset);
    if !asset.exists() {
        return Err(format!("file not found: {}", args.asset));
    }
    let action = parse_action(&args.action)?;
    let seed = load_signer_seed(&args.seed_file)?;
    let signer = Signer::from_seed(&seed).map_err(|e| format!("signer: {e}"))?;

    let sidecar = args
        .sidecar
        .unwrap_or_else(|| opm::sidecar_path(asset).to_string_lossy().into_owned());
    let sidecar_path = Path::new(&sidecar);
    if !sidecar_path.exists() {
        return Err(format!(
            "manifest not found: {sidecar} (run 'create' first)"
        ));
    }
    let mut opm = opm::load(sidecar_path).map_err(|e| format!("load: {e}"))?;

    // The asset is read INSIDE append_edit — after the edit has landed.
    opm.append_edit(asset, &signer, action, args.note.as_deref())
        .map_err(|e| format!("append: {e}"))?;
    opm::save(&opm, sidecar_path).map_err(|e| format!("save {sidecar}: {e}"))?;

    println!("Edit appended: {sidecar}");
    println!(
        "  index:     {}",
        opm.edits.last().map(|e| e.index).unwrap_or(0)
    );
    println!("  action:    {}", args.action);
    println!("  checkpoints: {}", opm.checkpoints.len());
    Ok(())
}

fn cmd_attest(args: AttestArgs) -> Result<(), String> {
    let asset = Path::new(&args.asset);
    if !asset.exists() {
        return Err(format!("file not found: {}", args.asset));
    }
    let seed = load_signer_seed(&args.seed_file)?;
    let attestor = Signer::from_seed(&seed).map_err(|e| format!("attestor: {e}"))?;

    let sidecar = args
        .sidecar
        .unwrap_or_else(|| opm::sidecar_path(asset).to_string_lossy().into_owned());
    let sidecar_path = Path::new(&sidecar);
    if !sidecar_path.exists() {
        return Err(format!(
            "manifest not found: {sidecar} (run 'create' first)"
        ));
    }
    let mut opm = opm::load(sidecar_path).map_err(|e| format!("load: {e}"))?;
    opm.attest(&attestor).map_err(|e| format!("attest: {e}"))?;
    opm::save(&opm, sidecar_path).map_err(|e| format!("save {sidecar}: {e}"))?;

    println!("Attestation added: {sidecar}");
    println!("  attestor:  {}", attestor.fingerprint_hex());
    println!(
        "  manifest_id: {}",
        hex::encode(opm.manifest_id().map_err(|e| e.to_string())?)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamp_and_verify_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("doc.txt");
        std::fs::write(&file, b"important content").unwrap();

        let stamp_args = StampArgs {
            file: file.to_str().unwrap().to_string(),
            output: None,
        };
        assert!(cmd_stamp(stamp_args).is_ok());

        let stamp_file = dir.path().join("doc.txt.stamp.json");
        assert!(stamp_file.exists());

        let verify_args = VerifyArgs {
            file: file.to_str().unwrap().to_string(),
            stamp: stamp_file.to_str().unwrap().to_string(),
        };
        assert!(cmd_verify(verify_args).is_ok());
    }

    #[test]
    fn verify_detects_tamper() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("doc.txt");
        std::fs::write(&file, b"original").unwrap();

        let stamp_args = StampArgs {
            file: file.to_str().unwrap().to_string(),
            output: None,
        };
        cmd_stamp(stamp_args).unwrap();

        // Tamper
        std::fs::write(&file, b"modified!").unwrap();

        let stamp_file = dir.path().join("doc.txt.stamp.json");
        let verify_args = VerifyArgs {
            file: file.to_str().unwrap().to_string(),
            stamp: stamp_file.to_str().unwrap().to_string(),
        };
        assert!(cmd_verify(verify_args).is_err());
    }

    #[test]
    fn watermark_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("data.bin");
        std::fs::write(&file, b"binary content here").unwrap();

        let wm_args = WatermarkArgs {
            file: file.to_str().unwrap().to_string(),
            label: Some("test".into()),
            output: None,
        };
        assert!(cmd_watermark(wm_args).is_ok());

        let uw_args = UnwatermarkArgs {
            file: file.to_str().unwrap().to_string(),
            strip: None,
        };
        assert!(cmd_unwatermark(uw_args).is_ok());
    }

    #[test]
    fn scan_and_check() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
        std::fs::write(dir.path().join("b.txt"), b"beta").unwrap();

        let scan_args = ScanArgs {
            dir: dir.path().to_str().unwrap().to_string(),
            output: None,
        };
        assert!(cmd_scan(scan_args).is_ok());

        let manifest_path = dir.path().join("provenance-manifest.json");
        assert!(manifest_path.exists());

        let check_args = CheckArgs {
            dir: dir.path().to_str().unwrap().to_string(),
            manifest: manifest_path.to_str().unwrap().to_string(),
        };
        assert!(cmd_check(check_args).is_ok());
    }

    #[test]
    fn dispatch_all_commands() {
        use crate::cli::Cli;
        use clap::Parser;

        // Stamp
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("d.txt");
        std::fs::write(&file, b"dispatch test").unwrap();
        let cli = Cli::parse_from(["origin-provenance", "stamp", file.to_str().unwrap()]);
        assert!(dispatch(cli).is_ok());

        // Verify
        let stamp_file = dir.path().join("d.txt.stamp.json");
        let cli = Cli::parse_from([
            "origin-provenance",
            "verify",
            "--stamp",
            stamp_file.to_str().unwrap(),
            file.to_str().unwrap(),
        ]);
        assert!(dispatch(cli).is_ok());

        // Watermark
        let wm_file = dir.path().join("wm.txt");
        std::fs::write(&wm_file, b"watermark me").unwrap();
        let cli = Cli::parse_from(["origin-provenance", "watermark", wm_file.to_str().unwrap()]);
        assert!(dispatch(cli).is_ok());

        // Unwatermark
        let cli = Cli::parse_from([
            "origin-provenance",
            "unwatermark",
            wm_file.to_str().unwrap(),
        ]);
        assert!(dispatch(cli).is_ok());

        // Scan
        let scan_dir = tempfile::tempdir().unwrap();
        std::fs::write(scan_dir.path().join("s.txt"), b"scan").unwrap();
        let cli = Cli::parse_from([
            "origin-provenance",
            "scan",
            scan_dir.path().to_str().unwrap(),
        ]);
        assert!(dispatch(cli).is_ok());

        // Check
        let manifest_path = scan_dir.path().join("provenance-manifest.json");
        let cli = Cli::parse_from([
            "origin-provenance",
            "check",
            "--manifest",
            manifest_path.to_str().unwrap(),
            scan_dir.path().to_str().unwrap(),
        ]);
        assert!(dispatch(cli).is_ok());
    }

    #[test]
    fn stamp_file_not_found() {
        let args = StampArgs {
            file: "/nonexistent/file.txt".into(),
            output: None,
        };
        let err = cmd_stamp(args).unwrap_err();
        assert!(err.contains("file not found"));
    }

    #[test]
    fn verify_file_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let stamp = dir.path().join("s.json");
        std::fs::write(&stamp, b"{}").unwrap();
        let args = VerifyArgs {
            file: "/nonexistent/file.txt".into(),
            stamp: stamp.to_str().unwrap().into(),
        };
        let err = cmd_verify(args).unwrap_err();
        assert!(err.contains("file not found"));
    }

    #[test]
    fn verify_stamp_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("f.txt");
        std::fs::write(&file, b"data").unwrap();
        let args = VerifyArgs {
            file: file.to_str().unwrap().into(),
            stamp: "/nonexistent/stamp.json".into(),
        };
        let err = cmd_verify(args).unwrap_err();
        assert!(err.contains("stamp not found"));
    }

    #[test]
    fn watermark_file_not_found() {
        let args = WatermarkArgs {
            file: "/nonexistent/file.txt".into(),
            label: None,
            output: None,
        };
        let err = cmd_watermark(args).unwrap_err();
        assert!(err.contains("file not found"));
    }

    #[test]
    fn watermark_already_watermarked() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("wm.bin");
        std::fs::write(&file, b"content").unwrap();

        // First watermark
        let args = WatermarkArgs {
            file: file.to_str().unwrap().into(),
            label: None,
            output: None,
        };
        cmd_watermark(args).unwrap();

        // Second watermark should fail
        let args = WatermarkArgs {
            file: file.to_str().unwrap().into(),
            label: None,
            output: None,
        };
        let err = cmd_watermark(args).unwrap_err();
        assert!(err.contains("already contains a watermark"));
    }

    #[test]
    fn unwatermark_file_not_found() {
        let args = UnwatermarkArgs {
            file: "/nonexistent/file.txt".into(),
            strip: None,
        };
        let err = cmd_unwatermark(args).unwrap_err();
        assert!(err.contains("file not found"));
    }

    #[test]
    fn unwatermark_no_watermark() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("plain.txt");
        std::fs::write(&file, b"no watermark here").unwrap();
        let args = UnwatermarkArgs {
            file: file.to_str().unwrap().into(),
            strip: None,
        };
        let err = cmd_unwatermark(args).unwrap_err();
        assert!(err.contains("does not contain a watermark"));
    }

    #[test]
    fn unwatermark_with_strip() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("wm.bin");
        std::fs::write(&file, b"original data").unwrap();

        let wm_args = WatermarkArgs {
            file: file.to_str().unwrap().into(),
            label: Some("strip-test".into()),
            output: None,
        };
        cmd_watermark(wm_args).unwrap();

        let stripped = dir.path().join("stripped.bin");
        let uw_args = UnwatermarkArgs {
            file: file.to_str().unwrap().into(),
            strip: Some(stripped.to_str().unwrap().into()),
        };
        assert!(cmd_unwatermark(uw_args).is_ok());
        assert!(stripped.exists());
        assert_eq!(std::fs::read(&stripped).unwrap(), b"original data");
    }

    #[test]
    fn scan_not_a_directory() {
        let args = ScanArgs {
            dir: "/nonexistent/dir".into(),
            output: None,
        };
        let err = cmd_scan(args).unwrap_err();
        assert!(err.contains("not a directory"));
    }

    #[test]
    fn check_not_a_directory() {
        let args = CheckArgs {
            dir: "/nonexistent/dir".into(),
            manifest: "/some/manifest.json".into(),
        };
        let err = cmd_check(args).unwrap_err();
        assert!(err.contains("not a directory"));
    }

    #[test]
    fn check_manifest_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let args = CheckArgs {
            dir: dir.path().to_str().unwrap().into(),
            manifest: "/nonexistent/manifest.json".into(),
        };
        let err = cmd_check(args).unwrap_err();
        assert!(err.contains("manifest not found"));
    }

    #[test]
    fn check_detects_modified_and_missing() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("keep.txt"), b"keep").unwrap();
        std::fs::write(dir.path().join("modify.txt"), b"original").unwrap();
        std::fs::write(dir.path().join("delete.txt"), b"gone").unwrap();

        let scan_args = ScanArgs {
            dir: dir.path().to_str().unwrap().into(),
            output: None,
        };
        cmd_scan(scan_args).unwrap();

        // Modify one file, delete another
        std::fs::write(dir.path().join("modify.txt"), b"tampered!").unwrap();
        std::fs::remove_file(dir.path().join("delete.txt")).unwrap();

        let manifest_path = dir.path().join("provenance-manifest.json");
        let check_args = CheckArgs {
            dir: dir.path().to_str().unwrap().into(),
            manifest: manifest_path.to_str().unwrap().into(),
        };
        let err = cmd_check(check_args).unwrap_err();
        assert!(err.contains("integrity check failed"));
    }

    // ---- OPM manifest CLI (ticket P-02) ----

    fn seed_file(dir: &tempfile::TempDir, name: &str, seed: [u8; 32]) -> String {
        let p = dir.path().join(name);
        std::fs::write(&p, seed).unwrap();
        p.to_str().unwrap().to_string()
    }

    #[test]
    fn opm_create_append_attest_cli_flow() {
        use crate::cli::Cli;
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("movie.txt");
        std::fs::write(&file, b"scene one").unwrap();
        let signer_seed = seed_file(&dir, "signer.seed", [0xA1u8; 32]);
        let attestor_seed = seed_file(&dir, "attestor.seed", [0xB2u8; 32]);

        // create
        let cli = Cli::parse_from([
            "origin-provenance",
            "create",
            file.to_str().unwrap(),
            "--seed-file",
            &signer_seed,
            "--action",
            "capture",
        ]);
        assert!(dispatch(cli).is_ok());
        let sidecar = dir.path().join("movie.txt.opm");
        assert!(sidecar.exists(), "default sidecar <asset>.opm");

        // append (post-edit bytes bound)
        std::fs::write(&file, b"scene one, re-cut").unwrap();
        let cli = Cli::parse_from([
            "origin-provenance",
            "append",
            file.to_str().unwrap(),
            "--seed-file",
            &signer_seed,
            "--note",
            "re-cut",
        ]);
        assert!(dispatch(cli).is_ok());

        // attest
        let cli = Cli::parse_from([
            "origin-provenance",
            "attest",
            file.to_str().unwrap(),
            "--seed-file",
            &attestor_seed,
        ]);
        assert!(dispatch(cli).is_ok());

        // The sidecar reflects everything: 2 edits, 2 checkpoints, 1 attestation.
        let opm = opm::load(&sidecar).unwrap();
        assert_eq!(opm.edits.len(), 2);
        assert_eq!(opm.checkpoints.len(), 2);
        assert_eq!(opm.attestations.len(), 1);
        assert_eq!(opm.edits[1].note.as_deref(), Some("re-cut"));
        // Post-edit bytes bound (P4-a end to end).
        assert_eq!(
            opm.edits[1].content.whole_file_hash,
            hex::encode(opm::content::whole_file_hash(b"scene one, re-cut"))
        );
    }

    #[test]
    fn opm_cli_rejects_unknown_action_and_missing_files() {
        use crate::cli::Cli;
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("x.txt");
        std::fs::write(&file, b"x").unwrap();
        let seed = seed_file(&dir, "s.seed", [1u8; 32]);

        let cli = Cli::parse_from([
            "origin-provenance",
            "create",
            file.to_str().unwrap(),
            "--seed-file",
            &seed,
            "--action",
            "teleport",
        ]);
        let err = dispatch(cli).unwrap_err();
        assert!(err.contains("unknown action"), "got: {err}");

        let cli = Cli::parse_from([
            "origin-provenance",
            "create",
            "/nonexistent/asset.bin",
            "--seed-file",
            &seed,
        ]);
        let err = dispatch(cli).unwrap_err();
        assert!(err.contains("file not found"));

        let cli = Cli::parse_from([
            "origin-provenance",
            "create",
            file.to_str().unwrap(),
            "--seed-file",
            "/nonexistent/seed",
        ]);
        let err = dispatch(cli).unwrap_err();
        assert!(err.contains("seed file"));
    }

    #[test]
    fn opm_cli_append_requires_existing_manifest() {
        use crate::cli::Cli;
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("y.txt");
        std::fs::write(&file, b"y").unwrap();
        let seed = seed_file(&dir, "y.seed", [3u8; 32]);

        let cli = Cli::parse_from([
            "origin-provenance",
            "append",
            file.to_str().unwrap(),
            "--seed-file",
            &seed,
        ]);
        let err = dispatch(cli).unwrap_err();
        assert!(err.contains("manifest not found"), "got: {err}");
    }

    #[test]
    fn opm_cli_hex_seed_accepted() {
        use crate::cli::Cli;
        use clap::Parser;
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("h.txt");
        std::fs::write(&file, b"h").unwrap();
        let p = dir.path().join("hex.seed");
        std::fs::write(&p, hex::encode([5u8; 32])).unwrap();

        let cli = Cli::parse_from([
            "origin-provenance",
            "create",
            file.to_str().unwrap(),
            "--seed-file",
            p.to_str().unwrap(),
        ]);
        assert!(dispatch(cli).is_ok());
    }
}
