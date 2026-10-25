//! AuraClean `safety-guard` — Defense-in-Depth Windows Protection & Time-Capsule Vault.
//!
//! Designed and maintained by mjojo (https://github.com/mjojo/AuraClean).

pub mod cloud_and_age_guard;
pub mod lock_detector;
pub mod quarantine;
pub mod whitelist;

pub use cloud_and_age_guard::{
    AttributeSafetyVerdict, FILE_ATTRIBUTE_OFFLINE_FLAG,
    FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS_FLAG, FILE_ATTRIBUTE_RECALL_ON_OPEN_FLAG,
    FILE_ATTRIBUTE_REPARSE_POINT_FLAG, evaluate_win32_attributes, inspect_path_attributes,
    is_older_than_threshold,
};
pub use lock_detector::{
    FileLockStatus, inspect_files_lock_status, is_file_exclusively_openable,
    query_restart_manager_for_file,
};
pub use quarantine::{
    DEFAULT_MAX_SINGLE_FILE_ARCHIVE_BYTES, DEFAULT_MAX_VAULT_BYTES, DEFAULT_RETENTION_DAYS,
    DEFAULT_ZSTD_LEVEL, QuarantineCandidate, RegistrySnapshotEntry, TimeCapsuleVault, VaultConfig,
    export_windows_reg_format,
};
pub use whitelist::{
    IMMUTABLE_EXTENSIONS, IMMUTABLE_SYSTEM_PREFIXES, PROTECTED_BINARY_EXTENSIONS,
    WhitelistVerdict, evaluate_path_whitelist, normalize_for_comparison, to_extended_length_path,
    validate_rule_pattern_safety,
};

#[cfg(test)]
mod tests {
    use super::*;
    use ipc_protocol::QuarantineTier;
    use std::fs::{self, OpenOptions};
    use std::io::Write;
    use std::path::Path;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn test_immutable_whitelist_blocks_critical_os_paths() {
        assert_eq!(
            evaluate_path_whitelist(Path::new(
                r"C:\Windows\WinSxS\amd64_microsoft-windows\file.bin"
            )),
            WhitelistVerdict::BlockedSystemDirectory(r"c:\windows\winsxs")
        );
        assert_eq!(
            evaluate_path_whitelist(Path::new(r"C:\Windows\System32\config\SAM")),
            WhitelistVerdict::BlockedSystemDirectory(r"c:\windows\system32\config")
        );
        assert_eq!(
            evaluate_path_whitelist(Path::new(r"C:\Windows\System32\drivers\ntfs.sys")),
            WhitelistVerdict::BlockedSystemDirectory(r"c:\windows\system32\drivers")
        );
        assert_eq!(
            evaluate_path_whitelist(Path::new(r"C:\Program Files\App\important.dll")),
            WhitelistVerdict::BlockedProtectedBinary("dll".to_string())
        );

        // Allowed temp & cache locations
        assert!(
            evaluate_path_whitelist(Path::new(
                r"C:\Users\Developer\AppData\Local\Temp\stale_installer.tmp"
            ))
            .is_allowed()
        );
        assert!(
            evaluate_path_whitelist(Path::new(
                r"C:\Users\Developer\AppData\Local\Temp\cached_helper.dll"
            ))
            .is_allowed()
        );
    }

    #[test]
    fn test_rule_pattern_sandbox_rejects_traversal_and_root_wildcards() {
        assert!(!validate_rule_pattern_safety(r"C:\*").is_allowed());
        assert!(!validate_rule_pattern_safety(r"%USERPROFILE%\*").is_allowed());
        assert!(!validate_rule_pattern_safety(r"%LOCALAPPDATA%\..\Documents\*").is_allowed());
        assert!(
            validate_rule_pattern_safety(
                r"%LOCALAPPDATA%\Google\Chrome\User Data\*\Cache\Cache_Data\*"
            )
            .is_allowed()
        );
    }

    #[test]
    fn test_cloud_placeholder_and_reparse_point_guards() {
        assert_eq!(
            evaluate_win32_attributes(0x0000_0020), // FILE_ATTRIBUTE_ARCHIVE
            AttributeSafetyVerdict::LocalNormalFile
        );
        assert_eq!(
            evaluate_win32_attributes(FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS_FLAG),
            AttributeSafetyVerdict::SkippedCloudPlaceholder
        );
        assert_eq!(
            evaluate_win32_attributes(FILE_ATTRIBUTE_RECALL_ON_OPEN_FLAG),
            AttributeSafetyVerdict::SkippedCloudPlaceholder
        );
        assert_eq!(
            evaluate_win32_attributes(FILE_ATTRIBUTE_REPARSE_POINT_FLAG),
            AttributeSafetyVerdict::SkippedReparsePoint
        );
    }

    #[test]
    fn test_file_age_guard_shields_newly_created_files() {
        let dir = tempdir().unwrap();
        let fresh_file = dir.path().join("fresh.tmp");
        fs::write(&fresh_file, b"active installer data").unwrap();

        // A newly created file should NOT be older than 24 hours
        assert!(
            !is_older_than_threshold(&fresh_file, Duration::from_secs(24 * 3600)).unwrap()
        );
        // Zero duration threshold allows immediate inspection
        assert!(is_older_than_threshold(&fresh_file, Duration::ZERO).unwrap());
    }

    #[test]
    fn test_win32_lock_detector_identifies_open_file_handles() {
        let dir = tempdir().unwrap();
        let locked_path = dir.path().join("locked_session.tmp");
        let unlocked_path = dir.path().join("unlocked_session.tmp");

        fs::write(&unlocked_path, b"unlocked content").unwrap();

        // Keep an open handle with exclusive or shared access to `locked_path`
        let mut open_handle = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&locked_path)
            .unwrap();
        open_handle.write_all(b"currently in use").unwrap();

        let statuses = inspect_files_lock_status(&[locked_path.clone(), unlocked_path.clone()]);
        assert!(statuses.get(&locked_path).unwrap().is_locked());
        assert_eq!(
            statuses.get(&unlocked_path).unwrap(),
            &FileLockStatus::Unlocked
        );

        drop(open_handle);
        assert!(is_file_exclusively_openable(&locked_path));
    }

    #[test]
    fn test_time_capsule_vault_quarantine_and_one_click_restore() {
        let workspace_dir = tempdir().unwrap();
        let vault_dir = workspace_dir.path().join("Vault");
        let temp_cache_dir = workspace_dir.path().join("AppData").join("Local").join("Temp");
        fs::create_dir_all(&temp_cache_dir).unwrap();

        let file_a = temp_cache_dir.join("shader_cache_01.bin");
        let file_b = temp_cache_dir.join("crash_dump_02.dmp");

        let payload_a = b"AuraClean test payload A - compressible binary stream ".repeat(64);
        let payload_b = b"AuraClean test payload B - diagnostic crash dump data ".repeat(32);

        fs::write(&file_a, &payload_a).unwrap();
        fs::write(&file_b, &payload_b).unwrap();

        let vault = TimeCapsuleVault::open(VaultConfig::new(&vault_dir)).unwrap();

        let candidates = vec![
            QuarantineCandidate {
                rule_id: "windows_user_temp".to_string(),
                path: file_a.clone(),
                requested_tier: QuarantineTier::ArchiveToVault,
            },
            QuarantineCandidate {
                rule_id: "windows_crash_dumps".to_string(),
                path: file_b.clone(),
                requested_tier: QuarantineTier::ArchiveToVault,
            },
        ];

        let reg_snapshots = vec![RegistrySnapshotEntry {
            root_hive: "HKEY_CURRENT_USER".to_string(),
            subkey_path: r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache".to_string(),
            value_name: Some(r"C:\Games\OldGame\game.exe.FriendlyAppName".to_string()),
            value_type: "REG_SZ".to_string(),
            value_data: "Old Game Launcher".to_string(),
            human_reason: "Orphaned MuiCache reference to missing executable".to_string(),
        }];

        let summary = vault.quarantine_batch(&candidates, &reg_snapshots).unwrap();

        assert_eq!(summary.archived_files_count, 2);
        assert_eq!(summary.manifest_only_count, 0);
        assert!(!file_a.exists(), "Original file A must be removed after archiving");
        assert!(!file_b.exists(), "Original file B must be removed after archiving");
        assert!(summary.archive_path.as_ref().unwrap().exists());
        assert!(summary.compressed_vault_bytes > 0);

        // Execute 1-Click Rollback
        let (restored_files, restored_reg) =
            vault.restore_transaction(summary.transaction_id).unwrap();
        assert_eq!(restored_files, 2);
        assert_eq!(restored_reg.len(), 1);
        assert!(file_a.exists(), "File A must be restored to original path");
        assert!(file_b.exists(), "File B must be restored to original path");
        assert_eq!(fs::read(&file_a).unwrap(), payload_a);
        assert_eq!(fs::read(&file_b).unwrap(), payload_b);
    }
}
