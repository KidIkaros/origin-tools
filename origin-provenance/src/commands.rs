// SPDX-License-Identifier: Apache-2.0

//! Command implementations for origin-provenance.

use std::path::Path;

use crate::cli::{
    CheckArgs, Commands, ScanArgs, StampArgs, UnwatermarkArgs, VerifyArgs, WatermarkArgs,
};
use crate::manifest::{FileStatus, Manifest};
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
}
