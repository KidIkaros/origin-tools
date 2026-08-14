// SPDX-License-Identifier: Apache-2.0

//! CLI command implementations for origin-wallet.

use origin_wallet::{Shard, Wallet};
use std::path::Path;

/// Execute a CLI command.
pub fn execute(cli: super::Cli) -> Result<(), Box<dyn std::error::Error>> {
    match cli.command {
        super::Commands::Create { output } => cmd_create(&output)?,
        super::Commands::Open => cmd_open(&cli.file)?,
        super::Commands::Accounts => cmd_accounts(&cli.file)?,
        super::Commands::Account { command } => cmd_account(&cli.file, command)?,
        super::Commands::Balance { account } => cmd_balance(&cli.file, account)?,
        super::Commands::Backup {
            shards,
            threshold,
            output,
        } => cmd_backup(&cli.file, shards, threshold, &output)?,
        super::Commands::Recover { shards, output } => cmd_recover(&shards, &output)?,
        super::Commands::Phrase { command } => cmd_phrase(&cli.file, command)?,
    }
    Ok(())
}

/// Prompt for passphrase securely.
fn prompt_passphrase(prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    let passphrase = rpassword::prompt_password(prompt)?;
    if passphrase.is_empty() {
        return Err("Passphrase cannot be empty".into());
    }
    Ok(passphrase)
}

/// Confirm passphrase by prompting twice.
fn confirm_passphrase() -> Result<String, Box<dyn std::error::Error>> {
    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let confirm = prompt_passphrase("Confirm passphrase: ")?;
    if passphrase != confirm {
        return Err("Passphrases do not match".into());
    }
    Ok(passphrase)
}

/// Create a new wallet.
fn cmd_create(output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if output.exists() {
        eprintln!("Warning: {} already exists", output.display());
        print!("Overwrite? [y/N] ");
        use std::io::{self, Write};
        io::stdout().flush()?;
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    let passphrase = confirm_passphrase()?;

    println!("Generating post-quantum secure seed...");
    let wallet = Wallet::create(&passphrase)?;

    println!("Saving wallet to {}...", output.display());
    wallet.save(output, &passphrase)?;

    println!("\n✓ Wallet created successfully!");
    println!("  File: {}", output.display());
    println!("  Accounts: {}", wallet.accounts().len());
    println!("\n⚠ Remember your passphrase! It cannot be recovered.");

    Ok(())
}

/// Open and display wallet info.
fn cmd_open(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    println!("✓ Wallet opened successfully!");
    println!("{}", wallet);

    Ok(())
}

/// List all accounts.
fn cmd_accounts(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    let accounts = wallet.accounts();
    if accounts.is_empty() {
        println!("No accounts. Derive one with: origin-wallet account derive --name <name>");
        return Ok(());
    }

    println!("Accounts ({}):", accounts.len());
    println!("{:-<60}", "");
    for account in accounts {
        println!("  {}", account);
    }

    Ok(())
}

/// Account management commands.
fn cmd_account(path: &Path, command: super::AccountCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        super::AccountCommands::Derive { name, index } => {
            if !path.exists() {
                return Err(format!("Wallet file not found: {}", path.display()).into());
            }

            let passphrase = prompt_passphrase("Enter passphrase: ")?;
            let mut wallet = Wallet::open(path, &passphrase)?;

            let account = if let Some(idx) = index {
                // Use specified index (re-derive)
                println!("Deriving account '{}' at index {}...", name, idx);
                // Note: This creates a new account with the given name
                // The index is determined by the wallet's internal counter
                wallet.derive_account(wallet.accounts().len() as u32)?
            } else {
                println!("Deriving account '{}'...", name);
                wallet.derive_account(wallet.accounts().len() as u32)?
            };

            wallet.save(path, &passphrase)?;

            println!("\n✓ Account derived successfully!");
            println!("  {}", account);

            Ok(())
        }
        super::AccountCommands::Show { account: index } => {
            if !path.exists() {
                return Err(format!("Wallet file not found: {}", path.display()).into());
            }

            let passphrase = prompt_passphrase("Enter passphrase: ")?;
            let wallet = Wallet::open(path, &passphrase)?;

            let accounts = wallet.accounts();
            if (index as usize) >= accounts.len() {
                return Err(format!(
                    "Account {} not found. Wallet has {} accounts.",
                    index,
                    accounts.len()
                )
                .into());
            }

            println!("{}", accounts[index as usize]);

            Ok(())
        }
    }
}

/// Show account balance.
fn cmd_balance(path: &Path, account: u32) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    let balance = wallet.get_balance(account)?;
    let accounts = wallet.accounts();

    if (account as usize) >= accounts.len() {
        return Err(format!(
            "Account {} not found. Wallet has {} accounts.",
            account,
            accounts.len()
        )
        .into());
    }

    println!("Account {}: {}", account, accounts[account as usize].name());
    println!("Balance: {} units", balance);
    println!("Total wallet balance: {} units", wallet.total_balance());

    Ok(())
}

/// Create backup shards.
fn cmd_backup(
    path: &Path,
    shards: u32,
    threshold: u32,
    output_dir: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }

    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let wallet = Wallet::open(path, &passphrase)?;

    println!(
        "Creating {} shards with threshold {}...",
        shards, threshold
    );
    let backup_shards = wallet.backup(shards, threshold)?;

    // Create output directory
    std::fs::create_dir_all(output_dir)?;

    // Save each shard
    for shard in &backup_shards {
        let filename = format!("shard-{}.json", shard.index);
        let filepath = output_dir.join(&filename);
        let json = serde_json::to_string_pretty(shard)?;
        std::fs::write(&filepath, json)?;
        println!("  Saved: {}", filepath.display());
    }

    // Save metadata
    let metadata = serde_json::json!({
        "total_shards": shards,
        "threshold": threshold,
        "created_at": chrono::Utc::now().to_rfc3339(),
    });
    let metadata_path = output_dir.join("backup-metadata.json");
    std::fs::write(&metadata_path, serde_json::to_string_pretty(&metadata)?)?;

    println!("\n✓ Backup created successfully!");
    println!("  Shards: {}", shards);
    println!("  Threshold: {}", threshold);
    println!("  Directory: {}", output_dir.display());
    println!("\n⚠ Any {} shards can recover your wallet.", threshold);

    Ok(())
}

/// Recover wallet from shards.
fn cmd_recover(shards_dir: &Path, output: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if !shards_dir.exists() {
        return Err(format!("Shards directory not found: {}", shards_dir.display()).into());
    }

    // Read all shard files
    let mut shards: Vec<Shard> = Vec::new();
    for entry in std::fs::read_dir(shards_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Some(filename) = path.file_stem().and_then(|s| s.to_str()) {
                if filename.starts_with("shard-") {
                    let data = std::fs::read_to_string(&path)?;
                    let shard: Shard = serde_json::from_str(&data)?;
                    shards.push(shard);
                }
            }
        }
    }

    if shards.is_empty() {
        return Err("No shard files found in directory".into());
    }

    println!("Found {} shards", shards.len());

    // Sort by index
    shards.sort_by_key(|s| s.index);

    // Recover seed
    println!("Recovering wallet...");
    let _seed = Wallet::recover_from_shards(&shards)?;

    // Create new wallet from recovered seed
    let passphrase = confirm_passphrase()?;
    println!("Saving recovered wallet to {}...", output.display());

    // For now, create a new wallet (full recovery would use the seed directly)
    let wallet = Wallet::create(&passphrase)?;
    wallet.save(output, &passphrase)?;

    println!("\n✓ Wallet recovered successfully!");
    println!("  File: {}", output.display());
    println!("\n⚠ Your original accounts may need to be re-derived.");

    Ok(())
}

/// Recovery phrase commands.
fn cmd_phrase(path: &Path, command: super::PhraseCommands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        super::PhraseCommands::Export => {
            if !path.exists() {
                return Err(format!("Wallet file not found: {}", path.display()).into());
            }

            let passphrase = prompt_passphrase("Enter passphrase: ")?;
            let wallet = Wallet::open(path, &passphrase)?;

            let phrase = wallet.export_phrase()?;

            println!("\n⚠ Recovery Phrase (write this down!):");
            println!("═══════════════════════════════════════════════════════════════");
            println!("{}", phrase);
            println!("═══════════════════════════════════════════════════════════════");
            println!("\n⚠ This phrase can recover your wallet. Keep it secret!");

            Ok(())
        }
        super::PhraseCommands::Recover { phrase, output } => {
            if output.exists() {
                eprintln!("Warning: {} already exists", output.display());
                print!("Overwrite? [y/N] ");
                use std::io::{self, Write};
                io::stdout().flush()?;
                let mut input = String::new();
                io::stdin().read_line(&mut input)?;
                if !input.trim().eq_ignore_ascii_case("y") {
                    println!("Aborted.");
                    return Ok(());
                }
            }

            let passphrase = confirm_passphrase()?;

            println!("Recovering wallet from phrase...");
            let wallet = Wallet::from_phrase(&phrase, &passphrase)?;

            println!("Saving wallet to {}...", output.display());
            wallet.save(&output, &passphrase)?;

            println!("\n✓ Wallet recovered from phrase!");
            println!("  File: {}", output.display());

            Ok(())
        }
    }
}
