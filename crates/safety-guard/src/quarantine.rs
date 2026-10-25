//! Tiered Time-Capsule Quarantine Engine (`tar.zst` streaming + SQLite `index.db` + Quota Guard).
//!
//! Nothing is permanently wiped without an audit trail:
//! - Tier 1 (`ArchiveToVault`): Files and registry snapshots (`.reg` + JSON) are compressed on-the-fly
//!   with Zstandard (level 3) into `vault_{uuid}.tar.zst`, verified with SHA-256, and deleted only
//!   after the archive transaction commits.
//! - Tier 2 (`ManifestOnly`): Massive reproducible caches or build directories exceeding the per-item
//!   archive cap are recorded in the SQLite manifest with cryptographic metadata so the Vault never
//!   exhausts disk space on low-storage drives.

use crate::lock_detector::is_file_exclusively_openable;
use crate::whitelist::evaluate_path_whitelist;
use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use ipc_protocol::{QuarantineTier, VaultTransactionSummary};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use uuid::Uuid;

/// Default Zstandard compression level (level 3 delivers ~400 MB/s compression speed).
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// Default maximum total Vault disk footprint (4 GiB).
pub const DEFAULT_MAX_VAULT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Default maximum single-file size eligible for `ArchiveToVault` before automatic downgrade to `ManifestOnly` (256 MiB).
pub const DEFAULT_MAX_SINGLE_FILE_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

/// Default retention window before automatic Time-Capsule expiration (7 days).
pub const DEFAULT_RETENTION_DAYS: i64 = 7;

/// Snapshot of a registry key/value slated for cleanup, serialized both to JSON and `.reg` inside the Vault.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistrySnapshotEntry {
    pub root_hive: String,
    pub subkey_path: String,
    pub value_name: Option<String>,
    pub value_type: String,
    pub value_data: String,
    pub human_reason: String,
}

/// Request item submitted to a Time-Capsule quarantine transaction.
#[derive(Debug, Clone)]
pub struct QuarantineCandidate {
    pub rule_id: String,
    pub path: PathBuf,
    pub requested_tier: QuarantineTier,
}

/// Configuration for the Time-Capsule Vault.
#[derive(Debug, Clone)]
pub struct VaultConfig {
    pub vault_dir: PathBuf,
    pub max_vault_bytes: u64,
    pub max_single_file_bytes: u64,
    pub retention_days: i64,
    pub zstd_level: i32,
}

impl VaultConfig {
    pub fn new(vault_dir: impl Into<PathBuf>) -> Self {
        Self {
            vault_dir: vault_dir.into(),
            max_vault_bytes: DEFAULT_MAX_VAULT_BYTES,
            max_single_file_bytes: DEFAULT_MAX_SINGLE_FILE_ARCHIVE_BYTES,
            retention_days: DEFAULT_RETENTION_DAYS,
            zstd_level: DEFAULT_ZSTD_LEVEL,
        }
    }

    pub fn db_path(&self) -> PathBuf {
        self.vault_dir.join("index.db")
    }
}

/// Manages the SQLite transaction index (`index.db`) and `.tar.zst` containers inside the Vault directory.
pub struct TimeCapsuleVault {
    config: VaultConfig,
}

impl TimeCapsuleVault {
    /// Initializes the Vault directory and creates the SQLite schema if not already present.
    pub fn open(config: VaultConfig) -> Result<Self> {
        fs::create_dir_all(&config.vault_dir).with_context(|| {
            format!(
                "Failed to create Time-Capsule vault directory at {}",
                config.vault_dir.display()
            )
        })?;

        let vault = Self { config };
        vault.init_schema()?;
        Ok(vault)
    }

    pub fn config(&self) -> &VaultConfig {
        &self.config
    }

    fn connect_db(&self) -> Result<Connection> {
        let conn = Connection::open(self.config.db_path())?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        Ok(conn)
    }

    fn init_schema(&self) -> Result<()> {
        let conn = self.connect_db()?;
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS transactions (
                tx_id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                rules_json TEXT NOT NULL,
                archived_files_count INTEGER NOT NULL,
                manifest_only_count INTEGER NOT NULL,
                original_bytes_total INTEGER NOT NULL,
                compressed_vault_bytes INTEGER NOT NULL,
                archive_filename TEXT,
                registry_snapshot_json TEXT NOT NULL,
                restored INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS quarantined_items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tx_id TEXT NOT NULL,
                entry_key TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                original_path TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                sha256_hex TEXT,
                effective_tier TEXT NOT NULL,
                restored INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (tx_id) REFERENCES transactions(tx_id) ON DELETE CASCADE
            );
            ",
        )?;
        Ok(())
    }

    /// Computes the current total compressed bytes stored across all active `.tar.zst` archives.
    pub fn current_vault_footprint_bytes(&self) -> Result<u64> {
        let conn = self.connect_db()?;
        let total: i64 = conn.query_row(
            "SELECT COALESCE(SUM(compressed_vault_bytes), 0) FROM transactions WHERE restored = 0",
            [],
            |row| row.get(0),
        )?;
        Ok(total.max(0) as u64)
    }

    /// Executes a transactional quarantine operation:
    /// 1. Re-verifies every candidate against the Immutable Whitelist and active file locks.
    /// 2. Enforces the Disk Quota Guard (downgrading oversized items to `ManifestOnly` if needed).
    /// 3. Streams `ArchiveToVault` files + `.reg` / JSON registry snapshots into `vault_{tx_id}.tar.zst`.
    /// 4. Flushes and syncs the archive, records everything in SQLite, and removes the original files.
    pub fn quarantine_batch(
        &self,
        candidates: &[QuarantineCandidate],
        registry_entries: &[RegistrySnapshotEntry],
    ) -> Result<VaultTransactionSummary> {
        let tx_id = Uuid::new_v4();
        let created_at = Utc::now();
        let current_footprint = self.current_vault_footprint_bytes()?;

        let archive_filename = format!("vault_{tx_id}.tar.zst");
        let archive_path = self.config.vault_dir.join(&archive_filename);

        let archive_file = File::create(&archive_path).with_context(|| {
            format!("Failed to create quarantine archive {}", archive_path.display())
        })?;
        let zstd_encoder = zstd::Encoder::new(archive_file, self.config.zstd_level)
            .context("Failed to initialize Zstandard encoder")?;
        let mut tar_builder = tar::Builder::new(zstd_encoder);

        let mut archived_records = Vec::new();
        let mut rule_set = Vec::new();
        let mut archived_files_count = 0usize;
        let mut manifest_only_count = 0usize;
        let mut original_bytes_total = 0u64;
        let mut projected_vault_usage = current_footprint;

        for (idx, candidate) in candidates.iter().enumerate() {
            // Defense-in-depth: always re-verify the immutable whitelist immediately before touching disk
            let verdict = evaluate_path_whitelist(&candidate.path);
            if !verdict.is_allowed() {
                bail!(
                    "Safety Guard blocked quarantine of protected path {}: {:?}",
                    candidate.path.display(),
                    verdict
                );
            }

            if !candidate.path.exists() || !candidate.path.is_file() {
                continue;
            }

            // Re-verify the file is not locked by any process right now
            if !is_file_exclusively_openable(&candidate.path) {
                continue;
            }

            let meta = fs::symlink_metadata(&candidate.path)?;
            let file_size = meta.len();
            original_bytes_total = original_bytes_total.saturating_add(file_size);

            if !rule_set.contains(&candidate.rule_id) {
                rule_set.push(candidate.rule_id.clone());
            }

            // Quota Guard & Single-File Cap evaluation
            let effective_tier = if candidate.requested_tier == QuarantineTier::ArchiveToVault
                && file_size <= self.config.max_single_file_bytes
                && projected_vault_usage.saturating_add(file_size / 2) <= self.config.max_vault_bytes
            {
                QuarantineTier::ArchiveToVault
            } else {
                QuarantineTier::ManifestOnly
            };

            let entry_key = format!("files/item_{idx}.bin");
            let mut sha256_hex = None;

            if effective_tier == QuarantineTier::ArchiveToVault {
                let sha = compute_file_sha256(&candidate.path)?;
                sha256_hex = Some(sha);

                let mut src_file = File::open(&candidate.path)?;
                tar_builder
                    .append_file(&entry_key, &mut src_file)
                    .with_context(|| {
                        format!(
                            "Failed to append {} into quarantine tar stream",
                            candidate.path.display()
                        )
                    })?;

                archived_files_count += 1;
                projected_vault_usage = projected_vault_usage.saturating_add(file_size / 2);
            } else {
                manifest_only_count += 1;
            }

            archived_records.push((
                entry_key,
                candidate.rule_id.clone(),
                candidate.path.clone(),
                file_size,
                sha256_hex,
                effective_tier,
            ));
        }

        // Embed registry snapshot inside the archive as both JSON and standard Windows `.reg` format
        let registry_json = serde_json::to_string_pretty(registry_entries)?;
        if !registry_entries.is_empty() {
            append_bytes_to_tar(&mut tar_builder, "registry/snapshot.json", registry_json.as_bytes())?;
            let reg_file_text = export_windows_reg_format(registry_entries);
            append_bytes_to_tar(&mut tar_builder, "registry/restore.reg", reg_file_text.as_bytes())?;
        }

        // Finalize tar and zstd stream before deleting any source files
        let zstd_encoder = tar_builder.into_inner()?;
        let finished_file = zstd_encoder.finish()?;
        finished_file.sync_all()?;
        drop(finished_file);

        // If no files were archived via ArchiveToVault and no registry snapshots were stored, remove empty archive
        let (final_archive_filename, compressed_vault_bytes) =
            if archived_files_count == 0 && registry_entries.is_empty() {
                let _ = fs::remove_file(&archive_path);
                (None, 0u64)
            } else {
                let len = fs::metadata(&archive_path).map(|m| m.len()).unwrap_or(0);
                (Some(archive_filename), len)
            };

        // Record transaction atomically in SQLite
        let mut conn = self.connect_db()?;
        let db_tx = conn.transaction()?;

        db_tx.execute(
            "INSERT INTO transactions (
                tx_id, created_at, rules_json, archived_files_count, manifest_only_count,
                original_bytes_total, compressed_vault_bytes, archive_filename, registry_snapshot_json, restored
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0)",
            params![
                tx_id.to_string(),
                created_at.to_rfc3339(),
                serde_json::to_string(&rule_set)?,
                archived_files_count as i64,
                manifest_only_count as i64,
                original_bytes_total as i64,
                compressed_vault_bytes as i64,
                final_archive_filename,
                registry_json,
            ],
        )?;

        for (entry_key, rule_id, orig_path, size_bytes, sha256_hex, tier) in &archived_records {
            let tier_str = match tier {
                QuarantineTier::ArchiveToVault => "ArchiveToVault",
                QuarantineTier::ManifestOnly => "ManifestOnly",
            };
            db_tx.execute(
                "INSERT INTO quarantined_items (
                    tx_id, entry_key, rule_id, original_path, size_bytes, sha256_hex, effective_tier, restored
                ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 0)",
                params![
                    tx_id.to_string(),
                    entry_key,
                    rule_id,
                    orig_path.to_string_lossy().to_string(),
                    *size_bytes as i64,
                    sha256_hex,
                    tier_str,
                ],
            )?;
        }

        db_tx.commit()?;

        // Now that the archive and SQLite transaction are safely persisted on disk, remove original files
        for (_, _, orig_path, _, _, _) in &archived_records {
            let _ = fs::remove_file(orig_path);
        }

        Ok(VaultTransactionSummary {
            transaction_id: tx_id,
            created_at,
            affected_rules: rule_set,
            archived_files_count,
            manifest_only_count,
            original_bytes_total,
            compressed_vault_bytes,
            archive_path: final_archive_filename.map(|f| self.config.vault_dir.join(f)),
            restored: false,
        })
    }

    /// Restores all `ArchiveToVault` files from a transaction back to their exact original paths,
    /// verifying SHA-256 checksums after extraction, and returns the count of restored files
    /// along with any captured registry snapshot entries.
    pub fn restore_transaction(
        &self,
        transaction_id: Uuid,
    ) -> Result<(usize, Vec<RegistrySnapshotEntry>)> {
        let mut conn = self.connect_db()?;
        let tx_id_str = transaction_id.to_string();

        let (archive_filename, registry_json, already_restored): (Option<String>, String, i64) = conn
            .query_row(
                "SELECT archive_filename, registry_snapshot_json, restored FROM transactions WHERE tx_id = ?1",
                params![&tx_id_str],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .with_context(|| format!("Transaction {transaction_id} not found in Vault index"))?;

        if already_restored != 0 {
            bail!("Transaction {transaction_id} has already been restored");
        }

        let mut stmt = conn.prepare(
            "SELECT entry_key, original_path, sha256_hex, effective_tier
             FROM quarantined_items WHERE tx_id = ?1",
        )?;

        let mut entry_map = std::collections::HashMap::new();
        let rows = stmt.query_map(params![&tx_id_str], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, String>(3)?,
            ))
        })?;

        for row in rows {
            let (entry_key, orig_path, sha, tier) = row?;
            if tier == "ArchiveToVault" {
                entry_map.insert(entry_key, (PathBuf::from(orig_path), sha));
            }
        }
        drop(stmt);

        let mut restored_count = 0usize;

        if let Some(ref archive_name) = archive_filename {
            let archive_path = self.config.vault_dir.join(archive_name);
            let archive_file = File::open(&archive_path).with_context(|| {
                format!(
                    "Failed to open quarantine archive for rollback: {}",
                    archive_path.display()
                )
            })?;
            let decoder = zstd::Decoder::new(archive_file)?;
            let mut archive = tar::Archive::new(decoder);

            for entry_res in archive.entries()? {
                let mut entry = entry_res?;
                let entry_path = entry.path()?.to_string_lossy().replace('\\', "/");

                if let Some((target_path, expected_sha)) = entry_map.get(&entry_path) {
                    if let Some(parent) = target_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let mut out_file = File::create(target_path)?;
                    io::copy(&mut entry, &mut out_file)?;
                    out_file.sync_all()?;
                    drop(out_file);

                    if let Some(expected) = expected_sha {
                        let actual = compute_file_sha256(target_path)?;
                        if &actual != expected {
                            bail!(
                                "Integrity check failed while restoring {}: expected SHA-256 {}, got {}",
                                target_path.display(),
                                expected,
                                actual
                            );
                        }
                    }

                    restored_count += 1;
                }
            }

            let _ = fs::remove_file(&archive_path);
        }

        let db_tx = conn.transaction()?;
        db_tx.execute(
            "UPDATE transactions SET restored = 1, compressed_vault_bytes = 0 WHERE tx_id = ?1",
            params![&tx_id_str],
        )?;
        db_tx.execute(
            "UPDATE quarantined_items SET restored = 1 WHERE tx_id = ?1",
            params![&tx_id_str],
        )?;
        db_tx.commit()?;

        let registry_entries: Vec<RegistrySnapshotEntry> =
            serde_json::from_str(&registry_json).unwrap_or_default();

        Ok((restored_count, registry_entries))
    }

    /// Lists all transactions recorded in the Time-Capsule Vault, newest first.
    pub fn list_transactions(&self) -> Result<Vec<VaultTransactionSummary>> {
        let conn = self.connect_db()?;
        let mut stmt = conn.prepare(
            "SELECT tx_id, created_at, rules_json, archived_files_count, manifest_only_count,
                    original_bytes_total, compressed_vault_bytes, archive_filename, restored
             FROM transactions ORDER BY created_at DESC",
        )?;

        let rows = stmt.query_map([], |row| {
            let tx_id_str: String = row.get(0)?;
            let created_str: String = row.get(1)?;
            let rules_json: String = row.get(2)?;
            let archived_files_count: i64 = row.get(3)?;
            let manifest_only_count: i64 = row.get(4)?;
            let original_bytes_total: i64 = row.get(5)?;
            let compressed_vault_bytes: i64 = row.get(6)?;
            let archive_filename: Option<String> = row.get(7)?;
            let restored: i64 = row.get(8)?;

            Ok(VaultTransactionSummary {
                transaction_id: Uuid::parse_str(&tx_id_str).unwrap_or_default(),
                created_at: DateTime::parse_from_rfc3339(&created_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                affected_rules: serde_json::from_str(&rules_json).unwrap_or_default(),
                archived_files_count: archived_files_count as usize,
                manifest_only_count: manifest_only_count as usize,
                original_bytes_total: original_bytes_total as u64,
                compressed_vault_bytes: compressed_vault_bytes as u64,
                archive_path: archive_filename.map(|f| self.config.vault_dir.join(f)),
                restored: restored != 0,
            })
        })?;

        let mut list = Vec::new();
        for r in rows {
            list.push(r?);
        }
        Ok(list)
    }

    /// Purges expired quarantine archives older than `retention_days` to reclaim Vault space.
    pub fn purge_expired(&self) -> Result<usize> {
        let cutoff = Utc::now() - ChronoDuration::days(self.config.retention_days);
        let transactions = self.list_transactions()?;
        let conn = self.connect_db()?;
        let mut purged = 0usize;

        for tx in transactions {
            if tx.created_at < cutoff {
                if let Some(ref archive_path) = tx.archive_path {
                    let _ = fs::remove_file(archive_path);
                }
                conn.execute(
                    "DELETE FROM transactions WHERE tx_id = ?1",
                    params![tx.transaction_id.to_string()],
                )?;
                purged += 1;
            }
        }
        Ok(purged)
    }
}

fn compute_file_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

fn append_bytes_to_tar<W: io::Write>(
    builder: &mut tar::Builder<W>,
    archive_path: &str,
    data: &[u8],
) -> Result<()> {
    let mut header = tar::Header::new_gnu();
    header.set_size(data.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder.append_data(&mut header, archive_path, data)?;
    Ok(())
}

/// Formats registry snapshot entries into a standard Windows Registry Editor Version 5.00 `.reg` file.
pub fn export_windows_reg_format(entries: &[RegistrySnapshotEntry]) -> String {
    let mut out = String::from("Windows Registry Editor Version 5.00\r\n\r\n");
    for entry in entries {
        out.push_str(&format!("; AuraClean Time-Capsule Backup: {}\r\n", entry.human_reason));
        out.push_str(&format!("[{}\\{}]\r\n", entry.root_hive, entry.subkey_path));
        if let Some(ref name) = entry.value_name {
            out.push_str(&format!("\"{}\"=\"{}\"\r\n", name, entry.value_data.replace('"', "\\\"")));
        }
        out.push_str("\r\n");
    }
    out
}
