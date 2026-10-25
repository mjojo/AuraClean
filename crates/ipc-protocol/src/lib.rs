//! Typed IPC contracts, multilingual primitives, and safety models for AuraClean.
//!
//! Designed and maintained by mjojo (https://github.com/mjojo/AuraClean).

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use uuid::Uuid;

/// Canonical Windows Named Pipe endpoint for privilege separation.
pub const DEFAULT_NAMED_PIPE_PATH: &str = r"\\.\pipe\AuraCleanPrivilegedService";

/// Supported UI & rule localization languages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Locale {
    #[default]
    En,
    Ru,
}

impl Locale {
    pub fn code(self) -> &'static str {
        match self {
            Self::En => "en",
            Self::Ru => "ru",
        }
    }

    pub fn from_code(code: &str) -> Self {
        match code.trim().to_ascii_lowercase().as_str() {
            "ru" | "ru-ru" | "rus" => Self::Ru,
            _ => Self::En,
        }
    }
}

/// Localized name and plain-language explanation attached to a cleaning rule or finding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizedText {
    pub name: String,
    pub description: String,
}

/// Multilingual text map keyed by language code (`en`, `ru`, ...).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalizedMap(pub HashMap<String, LocalizedText>);

impl LocalizedMap {
    pub fn resolve(&self, locale: Locale) -> Option<&LocalizedText> {
        self.0
            .get(locale.code())
            .or_else(|| self.0.get(Locale::En.code()))
            .or_else(|| self.0.values().next())
    }
}

/// Safety score assigned to every candidate item or rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SafetyLevel {
    /// 100% safe to clean (temp caches, crash dumps, stale logs).
    Green,
    /// Situational cleanup (shader caches, reproducible build directories).
    Yellow,
    /// Hard-blocked by default (system components, active files, SaveGames).
    Red,
}

/// Tiered quarantine strategy that prevents disk exhaustion during cleanup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum QuarantineTier {
    /// Stream-compress files and registry snapshots into `vault_{uuid}.tar.zst`.
    #[default]
    ArchiveToVault,
    /// Record cryptographic metadata and rebuild manifest in SQLite without duplicating gigabytes.
    ManifestOnly,
}

/// Explicit caller context passed from `auraclean-ui.exe` (User Session) to `auraclean-service.exe` (Session 0).
///
/// Prevents the SYSTEM service from accidentally resolving `%APPDATA%` or `HKCU`
/// to `C:\Windows\System32\config\systemprofile`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserContext {
    pub user_sid: String,
    pub user_profile_dir: PathBuf,
    pub local_appdata_dir: PathBuf,
    pub roaming_appdata_dir: PathBuf,
    pub preferred_locale: Locale,
}

/// Validated finding token issued by the scanner.
/// The elevated service only executes cleanups referencing issued finding tokens,
/// never arbitrary unvalidated paths from an IPC client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannedItem {
    pub item_id: Uuid,
    pub rule_id: String,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub safety_level: SafetyLevel,
    pub quarantine_tier: QuarantineTier,
    pub localized_title: String,
    pub localized_reason: String,
}

/// Requests sent from the User-Mode UI/CLI to the Elevated Service over the Named Pipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcRequest {
    Ping,
    ScanByRules {
        user_ctx: UserContext,
        rule_ids: Vec<String>,
    },
    ExecuteCleanup {
        user_ctx: UserContext,
        finding_ids: Vec<Uuid>,
        dry_run: bool,
    },
    RollbackTransaction {
        user_ctx: UserContext,
        transaction_id: Uuid,
    },
    ListVaultTransactions,
}

/// Summary of a reversible Time-Capsule transaction stored in `index.db`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VaultTransactionSummary {
    pub transaction_id: Uuid,
    pub created_at: DateTime<Utc>,
    pub affected_rules: Vec<String>,
    pub archived_files_count: usize,
    pub manifest_only_count: usize,
    pub original_bytes_total: u64,
    pub compressed_vault_bytes: u64,
    pub archive_path: Option<PathBuf>,
    pub restored: bool,
}

/// Responses returned by the Elevated Service to the User-Mode client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpcResponse {
    Pong {
        service_version: String,
        vendor: String,
    },
    ScanReport {
        items: Vec<ScannedItem>,
        skipped_locked: usize,
        skipped_cloud: usize,
        skipped_recent: usize,
        skipped_whitelisted: usize,
    },
    CleanupCommitted {
        transaction: VaultTransactionSummary,
    },
    RollbackCompleted {
        transaction_id: Uuid,
        restored_files_count: usize,
        restored_registry_keys: usize,
    },
    VaultTransactions {
        transactions: Vec<VaultTransactionSummary>,
    },
    Error {
        code: String,
        message: String,
    },
}
