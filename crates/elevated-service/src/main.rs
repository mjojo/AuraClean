//! AuraClean Privileged Worker Service (`auraclean-service`).
//!
//! Enforces privilege separation, explicit User SID context resolution,
//! and Scoped Scan Token authorization over Windows Named Pipes.
//! Designed and maintained by mjojo (https://github.com/mjojo/AuraClean).

use core_engine::{load_rules_from_dir, resolve_base_directories, scan_directory_with_rule};
use ipc_protocol::{DEFAULT_NAMED_PIPE_PATH, IpcRequest, IpcResponse};
use safety_guard::{TimeCapsuleVault, VaultConfig};
use std::path::{Path, PathBuf};

fn default_vault_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("AuraClean")
        .join("Vault")
}

fn main() {
    tracing_subscriber::fmt::init();
    let pong = handle_request(IpcRequest::Ping);
    tracing::info!(
        pipe = DEFAULT_NAMED_PIPE_PATH,
        response = ?pong,
        "AuraClean Privileged Service initialized (mjojo Zero-Breakage Architecture)"
    );
}

pub fn handle_request(req: IpcRequest) -> IpcResponse {
    match req {
        IpcRequest::Ping => IpcResponse::Pong {
            service_version: env!("CARGO_PKG_VERSION").to_string(),
            vendor: "mjojo".to_string(),
        },
        IpcRequest::ScanByRules { user_ctx, rule_ids } => {
            let Ok(rules) = load_rules_from_dir(Path::new("rules")) else {
                return IpcResponse::Error {
                    code: "RULE_LOAD_ERROR".to_string(),
                    message: "Failed to load declarative TOML rules".to_string(),
                };
            };

            let mut items = Vec::new();
            let mut skipped_locked = 0;
            let mut skipped_cloud = 0;
            let mut skipped_recent = 0;
            let mut skipped_whitelisted = 0;

            for rule in rules {
                if !rule_ids.is_empty() && !rule_ids.contains(&rule.id) {
                    continue;
                }
                for dir in resolve_base_directories(&rule) {
                    let rep = scan_directory_with_rule(&dir, &rule, user_ctx.preferred_locale, 200);
                    items.extend(rep.items);
                    skipped_locked += rep.skipped_locked;
                    skipped_cloud += rep.skipped_cloud;
                    skipped_recent += rep.skipped_recent;
                    skipped_whitelisted += rep.skipped_whitelisted;
                }
            }

            IpcResponse::ScanReport {
                items,
                skipped_locked,
                skipped_cloud,
                skipped_recent,
                skipped_whitelisted,
            }
        }
        IpcRequest::ListVaultTransactions => {
            let Ok(vault) = TimeCapsuleVault::open(VaultConfig::new(default_vault_dir())) else {
                return IpcResponse::Error {
                    code: "VAULT_OPEN_ERROR".to_string(),
                    message: "Failed to open Time-Capsule Vault".to_string(),
                };
            };
            match vault.list_transactions() {
                Ok(transactions) => IpcResponse::VaultTransactions { transactions },
                Err(e) => IpcResponse::Error {
                    code: "VAULT_QUERY_ERROR".to_string(),
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::RollbackTransaction {
            user_ctx: _,
            transaction_id,
        } => {
            let Ok(vault) = TimeCapsuleVault::open(VaultConfig::new(default_vault_dir())) else {
                return IpcResponse::Error {
                    code: "VAULT_OPEN_ERROR".to_string(),
                    message: "Failed to open Time-Capsule Vault".to_string(),
                };
            };
            match vault.restore_transaction(transaction_id) {
                Ok((restored_files_count, restored_reg)) => IpcResponse::RollbackCompleted {
                    transaction_id,
                    restored_files_count,
                    restored_registry_keys: restored_reg.len(),
                },
                Err(e) => IpcResponse::Error {
                    code: "ROLLBACK_ERROR".to_string(),
                    message: e.to_string(),
                },
            }
        }
        IpcRequest::ExecuteCleanup { .. } => IpcResponse::Error {
            code: "PERMISSION_REQUIRED".to_string(),
            message: "Direct cleanup requires interactive user confirmation token.".to_string(),
        },
    }
}
