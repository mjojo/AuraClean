//! Sprint 3: Zero-Risk Registry Inspector with Removable Drive Awareness (`GetDriveTypeW`)
//! and Localized Human-Readable Explanations (`en` / `ru`).
//!
//! Designed and maintained by mjojo (https://github.com/mjojo/AuraClean).

use crate::expand_windows_env_vars;
use ipc_protocol::{Locale, SafetyLevel};
use serde::{Deserialize, Serialize};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use uuid::Uuid;
use windows::Win32::Storage::FileSystem::GetDriveTypeW;
use windows::core::PCWSTR;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};

const DRIVE_NO_ROOT_DIR: u32 = 1;
const DRIVE_REMOVABLE: u32 = 2;
const DRIVE_FIXED: u32 = 3;
const DRIVE_REMOTE: u32 = 4;

/// Category of safe registry inspection zone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RegistryZone {
    AppPaths,
    MuiCache,
    StartupRun,
    FirewallRule,
}

/// Verified orphaned registry finding with human-readable multilingual explanations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RegistryFinding {
    pub finding_id: Uuid,
    pub zone: RegistryZone,
    pub root_hive: String,
    pub subkey_path: String,
    pub value_name: String,
    pub raw_value_data: String,
    pub resolved_exe_path: String,
    pub safety_level: SafetyLevel,
    pub title_en: String,
    pub reason_en: String,
    pub title_ru: String,
    pub reason_ru: String,
}

impl RegistryFinding {
    pub fn localized_title(&self, locale: Locale) -> &str {
        match locale {
            Locale::En => &self.title_en,
            Locale::Ru => &self.title_ru,
        }
    }

    pub fn localized_reason(&self, locale: Locale) -> &str {
        match locale {
            Locale::En => &self.reason_en,
            Locale::Ru => &self.reason_ru,
        }
    }
}

/// Parses a messy Windows Registry command line or icon string into a clean executable file path.
///
/// Examples handled:
/// - `"C:\Program Files\App\app.exe" --minimized -silent` -> `C:\Program Files\App\app.exe`
/// - `%LOCALAPPDATA%\Programs\App\app.exe,0` -> `<expanded>\Programs\App\app.exe`
/// - `C:\Games\Title\game.exe.FriendlyAppName` (MuiCache value name) -> `C:\Games\Title\game.exe`
pub fn extract_executable_path_from_registry_string(raw: &str) -> Option<PathBuf> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let expanded = expand_windows_env_vars(trimmed);

    // Strip MuiCache suffixes if present
    let without_mui = expanded
        .strip_suffix(".FriendlyAppName")
        .or_else(|| expanded.strip_suffix(".ApplicationCompany"))
        .unwrap_or(&expanded)
        .trim();

    // Ignore indirect shell hosts (`rundll32.exe`, `cmd.exe`, `msiexec.exe`, `powershell.exe`)
    let lower = without_mui.to_ascii_lowercase();
    if lower.starts_with("rundll32")
        || lower.starts_with("msiexec")
        || lower.starts_with("cmd.exe")
        || lower.starts_with("powershell")
        || lower.starts_with('@')
    {
        return None;
    }

    let candidate_str = if let Some(rest) = without_mui.strip_prefix('"') {
        rest.split('"').next()?
    } else {
        // Strip icon index `,0` or `,-101`
        let no_icon = without_mui.split(',').next().unwrap_or(without_mui);
        // Find `.exe` boundary if unquoted arguments follow
        let lower_no_icon = no_icon.to_ascii_lowercase();
        if let Some(exe_idx) = lower_no_icon.find(".exe") {
            &no_icon[..exe_idx + 4]
        } else {
            no_icon.split_whitespace().next()?
        }
    };

    let candidate = PathBuf::from(candidate_str.trim());
    if candidate.is_absolute() && candidate.extension().is_some() {
        Some(candidate)
    } else {
        None
    }
}

/// Checks whether the target path resides on a mounted fixed local drive.
///
/// Crucial Zero-Breakage Heuristic (Phase 3.2):
/// If a path points to `D:\` or `E:\` which is currently an unplugged USB drive (`DRIVE_NO_ROOT_DIR`),
/// a removable flash drive (`DRIVE_REMOVABLE`), or a disconnected network share (`DRIVE_REMOTE`),
/// we NEVER flag the registry key as broken!
pub fn is_on_mounted_fixed_drive(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    if path_str.len() < 3 || path_str.as_bytes()[1] != b':' {
        return false;
    }

    let root = format!("{}:\\", path_str.chars().next().unwrap_or('C'));
    let wide: Vec<u16> = std::ffi::OsStr::new(&root)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `wide` is a null-terminated root path like `"C:\\\0"`.
    let drive_type = unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) };

    drive_type == DRIVE_FIXED
        && drive_type != DRIVE_NO_ROOT_DIR
        && drive_type != DRIVE_REMOVABLE
        && drive_type != DRIVE_REMOTE
}

/// Determines whether a registry-referenced executable path is genuinely orphaned:
/// 1. Extracts the clean executable path.
/// 2. Verifies the target drive is a currently mounted fixed drive (`DRIVE_FIXED`).
/// 3. Confirms the file no longer exists on disk.
pub fn verify_orphaned_executable(raw: &str) -> Option<PathBuf> {
    let exe_path = extract_executable_path_from_registry_string(raw)?;
    if !is_on_mounted_fixed_drive(&exe_path) {
        return None;
    }
    if !exe_path.exists() {
        Some(exe_path)
    } else {
        None
    }
}

/// Scans the safe registry zones (`MuiCache`, `App Paths`, `Run`) in read-only mode
/// and produces localized, human-readable explanations for orphaned entries.
pub fn scan_safe_registry_zones(max_findings: usize) -> Vec<RegistryFinding> {
    let mut findings = Vec::new();

    // Zone 1: HKCU MuiCache (Explorer application name cache for deleted executables)
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let mui_subkey =
        r"Software\Classes\Local Settings\Software\Microsoft\Windows\Shell\MuiCache";
    if let Ok(mui_key) = hkcu.open_subkey_with_flags(mui_subkey, KEY_READ) {
        for val_res in mui_key.enum_values().flatten() {
            if findings.len() >= max_findings {
                return findings;
            }
            let (val_name, val_data) = val_res;
            if let Some(missing_exe) = verify_orphaned_executable(&val_name) {
                let app_label = val_data.to_string();
                let exe_display = missing_exe.display().to_string();
                let friendly_name = if app_label.trim().is_empty() {
                    missing_exe
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("Unknown Application")
                        .to_string()
                } else {
                    app_label.clone()
                };

                findings.push(RegistryFinding {
                    finding_id: Uuid::new_v4(),
                    zone: RegistryZone::MuiCache,
                    root_hive: "HKEY_CURRENT_USER".to_string(),
                    subkey_path: mui_subkey.to_string(),
                    value_name: val_name,
                    raw_value_data: app_label,
                    resolved_exe_path: exe_display.clone(),
                    safety_level: SafetyLevel::Green,
                    title_en: format!("Orphaned Explorer Cache — {friendly_name}"),
                    reason_en: format!(
                        "Leftover Windows Shell MuiCache entry for uninstalled program '{friendly_name}' (file {exe_display} no longer exists)."
                    ),
                    title_ru: format!("Остаточный кэш Проводника — {friendly_name}"),
                    reason_ru: format!(
                        "Устаревшая запись MuiCache от удаленной программы «{friendly_name}» (файл {exe_display} физически отсутствует на диске)."
                    ),
                });
            }
        }
    }

    // Zone 2: HKCU & HKLM App Paths
    let app_paths_subkey = r"Software\Microsoft\Windows\CurrentVersion\App Paths";
    for (hive_name, root_key) in [
        ("HKEY_CURRENT_USER", RegKey::predef(HKEY_CURRENT_USER)),
        ("HKEY_LOCAL_MACHINE", RegKey::predef(HKEY_LOCAL_MACHINE)),
    ] {
        if let Ok(ap_root) = root_key.open_subkey_with_flags(app_paths_subkey, KEY_READ) {
            for sub_name in ap_root.enum_keys().flatten() {
                if findings.len() >= max_findings {
                    return findings;
                }
                let full_sub = format!(r"{app_paths_subkey}\{sub_name}");
                if let Ok(sub_key) = root_key.open_subkey_with_flags(&full_sub, KEY_READ)
                    && let Ok(default_val) = sub_key.get_value::<String, _>("")
                    && let Some(missing_exe) = verify_orphaned_executable(&default_val)
                {
                    let exe_display = missing_exe.display().to_string();
                    findings.push(RegistryFinding {
                        finding_id: Uuid::new_v4(),
                        zone: RegistryZone::AppPaths,
                        root_hive: hive_name.to_string(),
                        subkey_path: full_sub,
                        value_name: "(Default)".to_string(),
                        raw_value_data: default_val,
                        resolved_exe_path: exe_display.clone(),
                        safety_level: SafetyLevel::Green,
                        title_en: format!("Orphaned App Path — {sub_name}"),
                        reason_en: format!(
                            "Broken application registration for '{sub_name}' pointing to missing executable {exe_display}."
                        ),
                        title_ru: format!("Осиротевший путь запуска (App Paths) — {sub_name}"),
                        reason_ru: format!(
                            "Битая ссылка регистрации приложения «{sub_name}» (исполняемый файл {exe_display} был удален)."
                        ),
                    });
                }
            }
        }
    }

    findings
}
