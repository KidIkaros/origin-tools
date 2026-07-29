// SPDX-License-Identifier: Apache-2.0

//! Command implementations for origin-provenance.

use std::path::{Path, PathBuf};

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

    let out_path = args.output.unwrap_or_else(|| format!("{}.stamp.json", args.file));
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
    println!("  integrity:     {}", if wm.verify(&original) { "✓ valid" } else { "✗ TAMPERED" });

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
}
