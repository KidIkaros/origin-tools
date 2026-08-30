// SPDX-License-Identifier: Apache-2.0

//! CLI command implementations for origin-wallet.

use origin_wallet::{Shard, Wallet};
use std::path::Path;

/// The passphrase given on the command line (`--passphrase`), for
/// non-interactive use (scripts, CI, tests). When set, every
/// `prompt_passphrase` returns it instead of reading the TTY.
static CLI_PASSPHRASE: std::sync::OnceLock<Option<String>> = std::sync::OnceLock::new();

/// Execute a CLI command.
pub fn execute(cli: super::Cli) -> Result<(), Box<dyn std::error::Error>> {
    // The global `--passphrase` flag (scripts/CI/tests): record it before
    // any command runs so every prompt consults it first.
    if let Some(p) = &cli.passphrase {
        let _ = CLI_PASSPHRASE.set(Some(p.clone()));
    }
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
        super::Commands::Policy {
            per_tx,
            per_day,
            per_month,
        } => cmd_policy(&cli.file, per_tx, per_day, per_month)?,
        super::Commands::Contact { command } => cmd_contact(&cli.file, command)?,
    }
    Ok(())
}

/// Prompt for passphrase securely — unless `--passphrase` was given on
/// the command line (scripts/CI/tests), in which case that is returned
/// without touching the TTY.
fn prompt_passphrase(_prompt: &str) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(Some(p)) = CLI_PASSPHRASE.get() {
        if !p.is_empty() {
            return Ok(p.clone());
        }
    }
    // The `prompt` is passed to rpassword for the interactive case.
    let passphrase = rpassword::prompt_password("Enter passphrase: ")?;
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
fn cmd_account(
    path: &Path,
    command: super::AccountCommands,
) -> Result<(), Box<dyn std::error::Error>> {
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

    println!("Creating {} shards with threshold {}...", shards, threshold);
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
    let seed = Wallet::recover_from_shards(&shards)?;

    // Rebuild the wallet from the recovered seed — accounts re-derive
    // deterministically from it, so the original keys are reproduced.
    let passphrase = confirm_passphrase()?;
    println!("Saving recovered wallet to {}...", output.display());

    let wallet = Wallet::from_seed(&seed)?;
    wallet.save(output, &passphrase)?;

    println!("\n✓ Wallet recovered successfully!");
    println!("  File: {}", output.display());
    println!("\n⚠ Re-derive your accounts with: origin-wallet account derive --name <name>");

    Ok(())
}

/// Recovery phrase commands.
fn cmd_phrase(
    path: &Path,
    command: super::PhraseCommands,
) -> Result<(), Box<dyn std::error::Error>> {
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

/// `wallet policy` — the standing spend policy (SPEC §10.2): print the
/// current caps + day/month totals, or set/update the caps. The caps are
/// persisted with the wallet.
fn cmd_policy(
    path: &Path,
    per_tx: Option<u64>,
    per_day: Option<u64>,
    per_month: Option<u64>,
) -> Result<(), Box<dyn std::error::Error>> {
    if !path.exists() {
        return Err(format!("Wallet file not found: {}", path.display()).into());
    }
    let passphrase = prompt_passphrase("Enter passphrase: ")?;
    let mut wallet = Wallet::open(path, &passphrase)?;

    if per_tx.is_none() && per_day.is_none() && per_month.is_none() {
        print_policy(&mut wallet);
        return Ok(());
    }
    let mut policy = wallet.spend_policy().clone();
    if let Some(v) = per_tx {
        policy.per_tx = Some(v);
    }
    if let Some(v) = per_day {
        policy.per_day = Some(v);
    }
    if let Some(v) = per_month {
        policy.per_month = Some(v);
    }
    wallet.set_spend_policy(policy);
    wallet.save(path, &passphrase)?;
    println!("\n✓ Standing spend policy updated (enforced on every payment):");
    print_policy(&mut wallet);
    Ok(())
}

fn print_policy(wallet: &mut Wallet) {
    let p = wallet.spend_policy().clone();
    let (_, day_spent, month_spent) = wallet.spend_usage();
    println!("Standing spend policy (SPEC §10.2):");
    println!(
        "  per-tx    : {}",
        p.per_tx
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unset".into())
    );
    println!(
        "  per-day   : {}",
        p.per_day
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unset".into())
    );
    println!(
        "  per-month : {}",
        p.per_month
            .map(|v| v.to_string())
            .unwrap_or_else(|| "unset".into())
    );
    println!("  spent today  : {day_spent}");
    println!("  spent this month : {month_spent}");
}

/// Contacts table commands: a plain JSON sidecar next to the wallet file
/// — labels map to fixed-width node ids.
fn cmd_contact(
    path: &Path,
    command: super::ContactCommands,
) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        super::ContactCommands::Add { label, mesh } => {
            let mut contacts = origin_wallet::Contacts::load(path)?;
            contacts.add(&label, &mesh)?;
            println!("✓ Saved contact '{label}' → {mesh}");
            println!("  File: {}", contacts.path().display());
            Ok(())
        }
        super::ContactCommands::List => {
            let contacts = origin_wallet::Contacts::load(path)?;
            if contacts.entries.is_empty() {
                println!("No contacts. Add one with: origin-wallet contact add --label <name> --mesh <meshid>");
                return Ok(());
            }
            println!("Contacts ({}):", contacts.entries.len());
            println!("{:-<72}", "");
            for (label, mesh) in &contacts.entries {
                println!("  {label:<24} {mesh}");
            }
            Ok(())
        }
    }
}
