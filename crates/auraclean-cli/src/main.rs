//! AuraClean Sprint 1 CLI Prototype (`auraclean-cli`).
//!
//! Demonstrates the multilingual UI catalog (`en` / `ru`), declarative TOML rule inspection,
//! Defense-in-Depth Safety Guards, and the Zstandard + SQLite Time-Capsule Vault.
//!
//! Architected by mjojo (https://github.com/mjojo/AuraClean).

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use core_engine::{load_rules_from_dir, resolve_base_directories, scan_directory_with_rule};
use ipc_protocol::Locale;
use safety_guard::{TimeCapsuleVault, VaultConfig};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Parser)]
#[command(
    name = "auraclean-cli",
    author = "mjojo <https://github.com/mjojo>",
    version,
    about = "AuraClean by mjojo — Next-Gen Hyper-Safe Windows Maintenance Suite (Sprint 1 Core)"
)]
struct Cli {
    /// Interface output language (`en` or `ru`).
    #[arg(short, long, default_value = "en", global = true)]
    lang: String,

    /// Path to the declarative TOML rules folder.
    #[arg(long, default_value = "rules", global = true)]
    rules_dir: PathBuf,

    /// Path to the Time-Capsule Quarantine Vault directory.
    #[arg(long, global = true)]
    vault_dir: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Display Vault status, loaded TOML rules, and safety guard configuration.
    Status,
    /// Run a non-destructive safety scan across loaded TOML rules (`--dry-run` enabled by default).
    Scan {
        /// Perform a non-destructive simulation without modifying any files.
        #[arg(long, default_value_t = true)]
        dry_run: bool,
        /// Maximum candidate files to inspect per rule directory during CLI preview.
        #[arg(long, default_value_t = 100)]
        limit_per_rule: usize,
    },
    /// Restore a previously quarantined transaction from the Time-Capsule Vault by UUID.
    Restore {
        /// Transaction UUID to roll back.
        tx_id: Uuid,
    },
}

fn default_vault_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("AuraClean")
        .join("Vault")
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let locale = Locale::from_code(&cli.lang);
    let vault_path = cli.vault_dir.unwrap_or_else(default_vault_dir);

    print_banner(locale);

    match cli.command {
        Commands::Status => {
            let rules = load_rules_from_dir(&cli.rules_dir)?;
            let vault = TimeCapsuleVault::open(VaultConfig::new(&vault_path))?;
            let transactions = vault.list_transactions()?;
            let footprint = vault.current_vault_footprint_bytes()?;

            match locale {
                Locale::En => {
                    println!("  [Vault Path]          {}", vault_path.display());
                    println!("  [Loaded Rules]        {} verified TOML rules", rules.len());
                    println!(
                        "  [Active Transactions] {} reversible cleanups in SQLite index",
                        transactions.iter().filter(|t| !t.restored).count()
                    );
                    println!(
                        "  [Vault Footprint]     {} bytes compressed (Max Quota: {} GiB)",
                        footprint,
                        vault.config().max_vault_bytes / (1024 * 1024 * 1024)
                    );
                    println!("\n  Loaded Declarative Rules:");
                }
                Locale::Ru => {
                    println!("  [Папка карантина]     {}", vault_path.display());
                    println!("  [Загружено правил]    {} проверенных TOML-правил", rules.len());
                    println!(
                        "  [Активные транзакции] {} доступных для отката в базе SQLite",
                        transactions.iter().filter(|t| !t.restored).count()
                    );
                    println!(
                        "  [Размер карантина]    {} байт в zstd (Квота: {} ГБ)",
                        footprint,
                        vault.config().max_vault_bytes / (1024 * 1024 * 1024)
                    );
                    println!("\n  Загруженные правила очистки:");
                }
            }

            for rule in &rules {
                let text = rule.localized(locale);
                println!(
                    "    • [{:?}] {} ({}) — {}",
                    rule.safety_level, rule.id, text.name, text.description
                );
            }
        }
        Commands::Scan {
            dry_run,
            limit_per_rule,
        } => {
            let rules = load_rules_from_dir(&cli.rules_dir)?;
            let mut total_items = 0usize;
            let mut total_bytes = 0u64;
            let mut skipped_locked = 0usize;
            let mut skipped_cloud = 0usize;
            let mut skipped_recent = 0usize;
            let mut skipped_whitelisted = 0usize;

            for rule in &rules {
                let text = rule.localized(locale);
                let dirs = resolve_base_directories(rule);
                let mut rule_items = 0usize;
                let mut rule_bytes = 0u64;

                for dir in dirs {
                    let rep = scan_directory_with_rule(&dir, rule, locale, limit_per_rule);
                    rule_items += rep.items.len();
                    rule_bytes += rep.total_reclaimable_bytes();
                    skipped_locked += rep.skipped_locked;
                    skipped_cloud += rep.skipped_cloud;
                    skipped_recent += rep.skipped_recent;
                    skipped_whitelisted += rep.skipped_whitelisted;
                }

                total_items += rule_items;
                total_bytes += rule_bytes;

                println!(
                    "  • [{:?}] {} -> {} items ({} KiB)",
                    rule.safety_level,
                    text.name,
                    rule_items,
                    rule_bytes / 1024
                );
            }

            println!();
            match locale {
                Locale::En => {
                    println!(
                        "  [Scan Summary (dry_run={})]: {} safe items found ({} KiB reclaimable)",
                        dry_run,
                        total_items,
                        total_bytes / 1024
                    );
                    println!(
                        "  [Safety Shields Triggered]: Locked={} | CloudPlaceholders={} | Recent(<24h)={} | Whitelisted={}",
                        skipped_locked, skipped_cloud, skipped_recent, skipped_whitelisted
                    );
                }
                Locale::Ru => {
                    println!(
                        "  [Итог сканирования (dry_run={})]: найдено {} безопасных файлов ({} КБ к очистке)",
                        dry_run,
                        total_items,
                        total_bytes / 1024
                    );
                    println!(
                        "  [Сработавшие щиты защиты]: ЗанятыПроцессом={} | Облачные(OneDrive)={} | Свежие(<24ч)={} | БелыйСписок={}",
                        skipped_locked, skipped_cloud, skipped_recent, skipped_whitelisted
                    );
                }
            }
        }
        Commands::Restore { tx_id } => {
            let vault = TimeCapsuleVault::open(VaultConfig::new(&vault_path))
                .context("Failed to open Time-Capsule Vault")?;
            let (restored_files, restored_reg) = vault.restore_transaction(tx_id)?;
            match locale {
                Locale::En => println!(
                    "  [Time-Capsule Rollback] Restored {} files and {} registry entries from transaction {}",
                    restored_files,
                    restored_reg.len(),
                    tx_id
                ),
                Locale::Ru => println!(
                    "  [Откат Time-Capsule] Восстановлено {} файлов и {} записей реестра из транзакции {}",
                    restored_files,
                    restored_reg.len(),
                    tx_id
                ),
            }
        }
    }

    Ok(())
}

fn print_banner(locale: Locale) {
    println!("========================================================================");
    match locale {
        Locale::En => {
            println!(
                "  ⚡ AuraClean v{} by mjojo — Hyper-Safe Windows Maintenance Suite",
                env!("CARGO_PKG_VERSION")
            );
            println!("  🛡  Zero-Breakage Safety Engine | Time-Capsule Zstd Vault");
        }
        Locale::Ru => {
            println!(
                "  ⚡ AuraClean v{} от mjojo — Сверхбезопасный комплекс очистки Windows",
                env!("CARGO_PKG_VERSION")
            );
            println!("  🛡  Ядро защиты Zero-Breakage | Карантин Time-Capsule (zstd)");
        }
    }
    println!("========================================================================\n");
}
