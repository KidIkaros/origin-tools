// SPDX-License-Identifier: Apache-2.0

//! Command implementations for origin-archive.
//!
//! Every command reads from stdin or a file, writes to stdout or a file,
//! and returns `Result<(), String>`. Errors go to stderr via `main.rs`.

use origin_common::{read_input, resolve_passphrase, tier_from_byte, tier_from_str};
use origin_crypto_sdk::{
    compress_encrypt, decompress_decrypt,
    compressed::{Compressor as SdkCompressor, HEADER_LEN, MAGIC, VERSION, CHUNK_TAG_SIZE},
};

use crate::cli::{ArchiveArgs, Cli, Commands, Compressor, InspectArgs, UnarchiveArgs};

pub fn dispatch(cli: Cli) -> Result<(), String> {
    match cli.command {
        Commands::Archive(args) => cmd_archive(args),
        Commands::Unarchive(args) => cmd_unarchive(args),
        Commands::Inspect(args) => cmd_inspect(args),
    }
}

/// Compress and encrypt data atomically.
pub fn cmd_archive(args: ArchiveArgs) -> Result<(), String> {
    let tier = tier_from_str(&args.tier)?;
    let algo = match args.compressor {
        Compressor::Zstd => SdkCompressor::Zstd,
        Compressor::Deflate => SdkCompressor::Deflate,
    };
    let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;

    let plaintext = read_input(args.input.as_deref().filter(|s| *s != "-"))?;
    let plaintext_len = plaintext.len();

    let container = compress_encrypt(
        &plaintext,
        passphrase.as_bytes(),
        tier,
        Some(algo),
        Some(args.chunk_size),
    )
    .map_err(|e| format!("archive failed: {e:?}"))?;

    // Securely zero the passphrase buffer.
    let mut pw = passphrase.into_bytes();
    for b in pw.iter_mut() {
        *b = 0;
    }

    origin_common::write_output(args.output.as_deref().filter(|s| *s != "-"), &container)?;

    if args.output.is_none() {
        eprintln!(
            "archived {} bytes -> {} bytes (compressor={:?}, tier={:?})",
            plaintext_len,
            container.len(),
            algo,
            tier,
        );
    }
    Ok(())
}

/// Decrypt and decompress data atomically.
pub fn cmd_unarchive(args: UnarchiveArgs) -> Result<(), String> {
    let passphrase = resolve_passphrase(args.passphrase_file.as_deref())?;

    let container = read_input(args.input.as_deref().filter(|s| *s != "-"))?;
    let container_len = container.len();

    let plaintext = decompress_decrypt(&container, passphrase.as_bytes())
        .map_err(|e| format!("unarchive failed: {e:?}"))?;

    // Securely zero the passphrase buffer.
    let mut pw = passphrase.into_bytes();
    for b in pw.iter_mut() {
        *b = 0;
    }

    origin_common::write_output(args.output.as_deref().filter(|s| *s != "-"), &plaintext)?;

    if args.output.is_none() {
        eprintln!(
            "unarchived {} bytes -> {} bytes",
            container_len,
            plaintext.len(),
        );
    }
    Ok(())
}

/// Inspect an archive's header without decrypting.
pub fn cmd_inspect(args: InspectArgs) -> Result<(), String> {
    let container = read_input(args.input.as_deref().filter(|s| *s != "-"))?;

    if container.len() < HEADER_LEN {
        return Err(format!(
            "input too short ({} bytes) to be an origin-archive container",
            container.len()
        ));
    }

    if &container[..4] != MAGIC {
        return Err("not an origin-archive container (bad magic)".to_string());
    }

    let version = container[4];
    if version != VERSION {
        return Err(format!(
            "unsupported version: {} (expected {})",
            version, VERSION
        ));
    }

    let tier = tier_from_byte(container[5])?;

    let algo_byte = container[6];
    let compressor = match SdkCompressor::from_byte(algo_byte) {
        Some(c) => c,
        None => return Err(format!("unknown compressor byte: {}", algo_byte)),
    };

    let salt = &container[9..25];
    let base_nonce = &container[25..49];
    let chunk_size = u32::from_be_bytes(
        container[49..53]
            .try_into()
            .map_err(|_| "chunk_size field parse failed")?,
    );
    let num_chunks = u32::from_be_bytes(
        container[53..57]
            .try_into()
            .map_err(|_| "num_chunks field parse failed")?,
    );

    let body_len = container.len() - HEADER_LEN;

    println!("origin-archive container header:");
    println!("  magic:          {}", String::from_utf8_lossy(&container[..4]));
    println!("  version:        {}", version);
    println!("  tier:           {:?}", tier);
    println!("  compressor:     {:?}", compressor);
    println!("  chunk_size:     {} bytes", chunk_size);
    println!("  num_chunks:     {}", num_chunks);
    println!("  salt (hex):     {}", hex::encode(salt));
    println!("  nonce (hex):    {}", hex::encode(base_nonce));
    println!("  body_len:       {} bytes", body_len);
    println!(
        "  tag_size/chunk: {} bytes (BLAKE3-MAC)",
        CHUNK_TAG_SIZE
    );

    Ok(())
}
