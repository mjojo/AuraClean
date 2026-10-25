//! Sprint 4–6 Deep Scanners:
//! - Hidden `AppData` (`Local`, `LocalLow`, `Roaming`, `ProgramData`) & `Documents` ("Мои документы") Analyzer
//! - Space Lens (Large Forgotten File Finder across Cyrillic & Hidden folders)
//! - Dev & Creator Cleaner (Stale `node_modules`, `target`, `.venv`, `.gradle`)
//! - Startup & Boot Impact Inspector (`HKCU\...\Run`, `HKLM\...\Run`, Startup folder)
//!
//! Full UTF-16 / Cyrillic path support (`C:\Users\Вит\...`, `Мои документы`) and SaveGame shielding.
//! Designed and maintained by mjojo (https://github.com/mjojo/AuraClean).

use crate::known_folders::{
    is_hidden_entry, query_known_folder, resolve_user_appdata_roots, resolve_user_documents_dirs,
};
use ipc_protocol::SafetyLevel;
use safety_guard::{
    AttributeSafetyVerdict, evaluate_path_whitelist, inspect_path_attributes,
};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::{Duration, SystemTime};
use windows::Win32::UI::Shell::FOLDERID_Profile;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ};

/// Summary entry for a scanned hidden `AppData` or `Documents` ("Мои документы") directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeepFolderInsight {
    pub category_label: String,
    pub folder_name: String,
    pub full_path: String,
    pub size_bytes: u64,
    pub file_count: usize,
    pub is_hidden: bool,
    pub has_cyrillic: bool,
    pub has_protected_savegames: bool,
    pub safety_level: SafetyLevel,
    pub note_en: String,
    pub note_ru: String,
}

/// Large forgotten file entry for Space Lens.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SpaceLensFileEntry {
    pub file_name: String,
    pub full_path: String,
    pub size_bytes: u64,
    pub days_since_modified: u64,
    pub is_hidden: bool,
    pub has_cyrillic: bool,
}

/// Startup program entry with estimated boot impact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupEntry {
    pub name: String,
    pub command: String,
    pub location: String,
    pub file_exists: bool,
    pub estimated_impact_ms: u32,
    pub impact_level: String,
}

/// Returns `true` if a path string contains any Cyrillic Unicode characters (`\u{0400}`..=`\u{04FF}`).
pub fn contains_cyrillic(text: &str) -> bool {
    text.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c))
}

/// Checks if a directory or file name matches common game save patterns so SaveGames are always shielded (`🛡`).
pub fn looks_like_savegame(path: &Path) -> bool {
    let lower = path.to_string_lossy().to_lowercase();
    lower.contains("savegame")
        || lower.contains("saved games")
        || lower.contains("\\saves\\")
        || lower.contains("сохранения")
        || lower.ends_with(".sav")
        || lower.ends_with(".save")
}

/// Scans the user's hidden `AppData` (`Local`, `LocalLow`, `Roaming`) and `Documents` (`Мои документы`)
/// folders to surface heavy cache/artifact folders, explicitly marking hidden attributes, Cyrillic paths,
/// and shielded SaveGames.
pub fn scan_hidden_appdata_and_documents(max_results: usize) -> Vec<DeepFolderInsight> {
    let mut insights = Vec::new();

    // 1. Scan hidden AppData roots (Local, LocalLow, Roaming)
    for (root_label, root_path) in resolve_user_appdata_roots() {
        if let Ok(entries) = std::fs::read_dir(&root_path) {
            for entry in entries.flatten().take(40) {
                let sub_path = entry.path();
                if !sub_path.is_dir() {
                    continue;
                }
                if !matches!(
                    inspect_path_attributes(&sub_path),
                    Ok(AttributeSafetyVerdict::LocalNormalFile)
                ) {
                    continue;
                }

                let (size_bytes, file_count, has_saves) =
                    compute_bounded_dir_metrics(&sub_path, 3, 250);
                if size_bytes < 512 * 1024 {
                    continue;
                }

                let path_str = sub_path.to_string_lossy().to_string();
                let folder_name = sub_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("App")
                    .to_string();
                let hidden = is_hidden_entry(&sub_path) || is_hidden_entry(&root_path);
                let cyrillic = contains_cyrillic(&path_str);

                insights.push(DeepFolderInsight {
                    category_label: format!("Hidden {root_label}"),
                    folder_name: folder_name.clone(),
                    full_path: path_str,
                    size_bytes,
                    file_count,
                    is_hidden: hidden,
                    has_cyrillic: cyrillic,
                    has_protected_savegames: has_saves,
                    safety_level: if has_saves {
                        SafetyLevel::Red
                    } else {
                        SafetyLevel::Yellow
                    },
                    note_en: format!(
                        "Hidden {root_label} folder for '{folder_name}' ({file_count} files inspected){}",
                        if has_saves { " • 🛡 SaveGames Shielded" } else { "" }
                    ),
                    note_ru: format!(
                        "Скрытая папка {root_label} приложения «{folder_name}» ({file_count} файлов){}",
                        if has_saves { " • 🛡 Сохранения защищены" } else { "" }
                    ),
                });
            }
        }
    }

    // 2. Scan User's "My Documents" / "Мои документы" (including Cyrillic & relocated paths)
    for docs_dir in resolve_user_documents_dirs() {
        if let Ok(entries) = std::fs::read_dir(&docs_dir) {
            for entry in entries.flatten().take(35) {
                let sub_path = entry.path();
                if !sub_path.is_dir() {
                    continue;
                }
                if !matches!(
                    inspect_path_attributes(&sub_path),
                    Ok(AttributeSafetyVerdict::LocalNormalFile)
                ) {
                    continue;
                }

                let (size_bytes, file_count, has_saves) =
                    compute_bounded_dir_metrics(&sub_path, 3, 250);
                if size_bytes < 64 * 1024 {
                    continue;
                }

                let path_str = sub_path.to_string_lossy().to_string();
                let folder_name = sub_path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("Documents")
                    .to_string();
                let hidden = is_hidden_entry(&sub_path);
                let cyrillic = contains_cyrillic(&path_str);

                insights.push(DeepFolderInsight {
                    category_label: "My Documents / Мои документы".to_string(),
                    folder_name: folder_name.clone(),
                    full_path: path_str,
                    size_bytes,
                    file_count,
                    is_hidden: hidden,
                    has_cyrillic: cyrillic,
                    has_protected_savegames: has_saves,
                    safety_level: if has_saves {
                        SafetyLevel::Red
                    } else {
                        SafetyLevel::Yellow
                    },
                    note_en: format!(
                        "Documents subfolder '{folder_name}' ({file_count} files){}",
                        if has_saves {
                            " • 🛡 SaveGames Protected"
                        } else {
                            ""
                        }
                    ),
                    note_ru: format!(
                        "Подпапка в «Мои документы»: «{folder_name}» ({file_count} файлов){}",
                        if has_saves {
                            " • 🛡 Сохранения защищены"
                        } else {
                            ""
                        }
                    ),
                });
            }
        }
    }

    insights.sort_by_key(|b| std::cmp::Reverse(b.size_bytes));
    insights.truncate(max_results);
    insights
}

fn compute_bounded_dir_metrics(
    dir: &Path,
    max_depth: usize,
    max_files: usize,
) -> (u64, usize, bool) {
    let mut total_bytes = 0u64;
    let mut count = 0usize;
    let mut has_saves = looks_like_savegame(dir);

    for entry_res in jwalk::WalkDir::new(dir)
        .follow_links(false)
        .skip_hidden(false)
        .max_depth(max_depth)
    {
        if count >= max_files {
            break;
        }
        let Ok(entry) = entry_res else {
            continue;
        };
        let p = entry.path();
        if looks_like_savegame(&p) {
            has_saves = true;
        }
        if entry.file_type().is_file()
            && let Ok(meta) = entry.metadata()
        {
            total_bytes = total_bytes.saturating_add(meta.len());
            count += 1;
        }
    }

    (total_bytes, count, has_saves)
}

/// Space Lens scanner: finds the largest files across the user's profile (including hidden `AppData`
/// and Cyrillic `Мои документы` folders) without touching cloud placeholders.
pub fn scan_space_lens_top_files(min_size_bytes: u64, limit: usize) -> Vec<SpaceLensFileEntry> {
    let mut results = Vec::new();
    let mut roots = Vec::new();

    if let Some(profile) = query_known_folder(&FOLDERID_Profile) {
        roots.push(profile);
    }
    for docs in resolve_user_documents_dirs() {
        if !roots.contains(&docs) {
            roots.push(docs);
        }
    }

    let now = SystemTime::now();

    for root in roots {
        let mut scanned_in_root = 0usize;
        for entry_res in jwalk::WalkDir::new(&root)
            .follow_links(false)
            .skip_hidden(false)
            .max_depth(4)
        {
            if scanned_in_root >= 2500 {
                break;
            }
            let Ok(entry) = entry_res else {
                continue;
            };
            if !entry.file_type().is_file() {
                continue;
            }
            scanned_in_root += 1;

            let path = entry.path();
            if !matches!(
                inspect_path_attributes(&path),
                Ok(AttributeSafetyVerdict::LocalNormalFile)
            ) {
                continue;
            }
            if !evaluate_path_whitelist(&path).is_allowed() {
                continue;
            }

            let Ok(meta) = entry.metadata() else {
                continue;
            };
            let len = meta.len();
            if len < min_size_bytes {
                continue;
            }

            let days = meta
                .modified()
                .ok()
                .and_then(|m| now.duration_since(m).ok())
                .unwrap_or(Duration::ZERO)
                .as_secs()
                / 86400;

            let full_path = path.to_string_lossy().to_string();
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("file")
                .to_string();

            results.push(SpaceLensFileEntry {
                file_name,
                has_cyrillic: contains_cyrillic(&full_path),
                is_hidden: is_hidden_entry(&path),
                full_path,
                size_bytes: len,
                days_since_modified: days,
            });
        }
    }

    results.sort_by_key(|b| std::cmp::Reverse(b.size_bytes));
    results.dedup_by(|a, b| a.full_path == b.full_path);
    results.truncate(limit);
    results
}

/// Inspects Windows Startup entries (`HKCU\...\Run` and `HKLM\...\Run`) and computes estimated
/// boot time impact in milliseconds.
pub fn scan_startup_entries() -> Vec<StartupEntry> {
    let mut list = Vec::new();
    let run_path = r"Software\Microsoft\Windows\CurrentVersion\Run";

    for (hive_label, root_key) in [
        ("HKCU\\...\\Run", RegKey::predef(HKEY_CURRENT_USER)),
        ("HKLM\\...\\Run", RegKey::predef(HKEY_LOCAL_MACHINE)),
    ] {
        if let Ok(sub) = root_key.open_subkey_with_flags(run_path, KEY_READ) {
            for (name, val) in sub.enum_values().flatten() {
                let cmd = val.to_string();
                let exe_opt =
                    crate::registry_inspector::extract_executable_path_from_registry_string(&cmd);
                let exists = exe_opt.as_ref().map(|p| p.exists()).unwrap_or(true);

                // Estimate boot impact based on binary size and known heavy updater signatures
                let size_mb = exe_opt
                    .as_ref()
                    .and_then(|p| std::fs::metadata(p).ok())
                    .map(|m| m.len() / (1024 * 1024))
                    .unwrap_or(5);
                let estimated_ms = ((size_mb as u32).saturating_mul(35)).clamp(120, 2400);
                let impact_level = if estimated_ms >= 900 {
                    "High"
                } else if estimated_ms >= 400 {
                    "Medium"
                } else {
                    "Low"
                };

                list.push(StartupEntry {
                    name,
                    command: cmd,
                    location: hive_label.to_string(),
                    file_exists: exists,
                    estimated_impact_ms: estimated_ms,
                    impact_level: impact_level.to_string(),
                });
            }
        }
    }

    list.sort_by_key(|b| std::cmp::Reverse(b.estimated_impact_ms));
    list
}
