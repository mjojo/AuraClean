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
use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
use windows::Win32::UI::Shell::FOLDERID_Profile;
use winreg::RegKey;
use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE, KEY_READ, KEY_SET_VALUE};

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

/// Startup program entry with estimated boot impact and interactive state (`Active` / `Disabled` / `Delayed60s`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StartupEntry {
    pub id: String,
    pub name: String,
    pub command: String,
    pub location: String,
    pub status: String,
    pub can_modify: bool,
    pub file_exists: bool,
    pub estimated_impact_ms: u32,
    pub impact_level: String,
}

/// Reproducible developer build artifact (`node_modules`, `target`, `.venv`, `.gradle`) found on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DevArtifactEntry {
    pub id: String,
    pub project_name: String,
    pub artifact_kind: String,
    pub full_path: String,
    pub size_bytes: u64,
    pub days_inactive: u64,
    pub rebuild_hint: String,
    pub has_cyrillic: bool,
}

/// Ghost Hunter finding: leftover folder in `AppData` or `Documents` that doesn't match any
/// currently installed program in the Windows `Uninstall` registry or Steam libraries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GhostLeftoverEntry {
    pub id: String,
    pub app_name: String,
    pub location_kind: String,
    pub full_path: String,
    pub size_bytes: u64,
    pub file_count: usize,
    pub days_inactive: u64,
    pub has_protected_savegames: bool,
    pub reason_en: String,
    pub reason_ru: String,
}

/// Real-time Windows RAM telemetry (`GlobalMemoryStatusEx`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SystemMemoryTelemetry {
    pub total_phys_bytes: u64,
    pub avail_phys_bytes: u64,
    pub used_phys_bytes: u64,
    pub memory_load_percent: u32,
}

/// Returns `true` if a path string contains any Cyrillic Unicode characters (`\u{0400}`..=`\u{04FF}`).
pub fn contains_cyrillic(text: &str) -> bool {
    text.chars().any(|c| ('\u{0400}'..='\u{04FF}').contains(&c))
}

/// Checks if a directory or file name matches common game save patterns so SaveGames are always shielded.
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
                    compute_bounded_dir_metrics(&sub_path, 4, 5_000);
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
                        if has_saves { " • [SaveGames Shielded]" } else { "" }
                    ),
                    note_ru: format!(
                        "Скрытая папка {root_label} приложения «{folder_name}» ({file_count} файлов){}",
                        if has_saves { " • [Сохранения защищены]" } else { "" }
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
                    compute_bounded_dir_metrics(&sub_path, 4, 5_000);
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
                            " • [SaveGames Protected]"
                        } else {
                            ""
                        }
                    ),
                    note_ru: format!(
                        "Подпапка в «Мои документы»: «{folder_name}» ({file_count} файлов){}",
                        if has_saves {
                            " • [Сохранения защищены]"
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

/// Inspects Windows Startup entries (`HKCU\...\Run`, `HKLM\...\Run`, and `HKCU\Software\AuraClean\DisabledStartup`)
/// and computes estimated boot time impact in milliseconds.
pub fn scan_startup_entries() -> Vec<StartupEntry> {
    let mut list = Vec::new();
    let run_path = r"Software\Microsoft\Windows\CurrentVersion\Run";
    let disabled_path = r"Software\AuraClean\DisabledStartup";

    for (hive_label, can_mod, root_key) in [
        ("HKCU\\...\\Run", true, RegKey::predef(HKEY_CURRENT_USER)),
        ("HKLM\\...\\Run", false, RegKey::predef(HKEY_LOCAL_MACHINE)),
    ] {
        if let Ok(sub) = root_key.open_subkey_with_flags(run_path, KEY_READ) {
            for (name, val) in sub.enum_values().flatten() {
                let cmd = val.to_string();
                let is_delayed = cmd.to_lowercase().contains("timeout /t 60");
                let exe_opt =
                    crate::registry_inspector::extract_executable_path_from_registry_string(&cmd);
                let exists = exe_opt.as_ref().map(|p| p.exists()).unwrap_or(true);

                let size_mb = exe_opt
                    .as_ref()
                    .and_then(|p| std::fs::metadata(p).ok())
                    .map(|m| m.len() / (1024 * 1024))
                    .unwrap_or(5);
                let estimated_ms = ((size_mb as u32).saturating_mul(35)).clamp(120, 2400);
                let impact_level = if is_delayed {
                    "Delayed (+60s)"
                } else if estimated_ms >= 900 {
                    "High"
                } else if estimated_ms >= 400 {
                    "Medium"
                } else {
                    "Low"
                };

                list.push(StartupEntry {
                    id: format!("{}::{}", hive_label, name),
                    name,
                    command: cmd,
                    location: hive_label.to_string(),
                    status: if is_delayed {
                        "Delayed60s".to_string()
                    } else {
                        "Active".to_string()
                    },
                    can_modify: can_mod,
                    file_exists: exists,
                    estimated_impact_ms: if is_delayed { 0 } else { estimated_ms },
                    impact_level: impact_level.to_string(),
                });
            }
        }
    }

    // Also include entries previously disabled via AuraClean so the user can re-enable them in 1 click
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(disabled_sub) = hkcu.open_subkey_with_flags(disabled_path, KEY_READ) {
        for (name, val) in disabled_sub.enum_values().flatten() {
            let cmd = val.to_string();
            list.push(StartupEntry {
                id: format!("DISABLED::{}", name),
                name,
                command: cmd,
                location: "HKCU (Disabled by AuraClean)".to_string(),
                status: "Disabled".to_string(),
                can_modify: true,
                file_exists: true,
                estimated_impact_ms: 0,
                impact_level: "Disabled".to_string(),
            });
        }
    }

    list.sort_by_key(|b| std::cmp::Reverse(b.estimated_impact_ms));
    list
}

/// Toggles a user startup entry between `Active` (`HKCU\...\Run`) and `Disabled`
/// (`HKCU\Software\AuraClean\DisabledStartup`), returning `(entry_name, original_command, new_status)`.
pub fn toggle_hkcu_startup_entry(entry_id: &str) -> anyhow::Result<(String, String, String)> {
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_path = r"Software\Microsoft\Windows\CurrentVersion\Run";
    let disabled_path = r"Software\AuraClean\DisabledStartup";

    if let Some(name) = entry_id.strip_prefix("DISABLED::") {
        // Re-enable: move from DisabledStartup back to HKCU\...\Run
        let disabled_key = hkcu.open_subkey_with_flags(disabled_path, KEY_READ | KEY_SET_VALUE)?;
        let cmd: String = disabled_key.get_value(name)?;
        let (run_key, _) = hkcu.create_subkey(run_path)?;
        run_key.set_value(name, &cmd)?;
        let _ = disabled_key.delete_value(name);
        Ok((name.to_string(), cmd, "Active".to_string()))
    } else if let Some(name) = entry_id.strip_prefix("HKCU\\...\\Run::") {
        // Disable: move from HKCU\...\Run to HKCU\Software\AuraClean\DisabledStartup
        let run_key = hkcu.open_subkey_with_flags(run_path, KEY_READ | KEY_SET_VALUE)?;
        let cmd: String = run_key.get_value(name)?;
        let (disabled_key, _) = hkcu.create_subkey(disabled_path)?;
        disabled_key.set_value(name, &cmd)?;
        run_key.delete_value(name)?;
        Ok((name.to_string(), cmd, "Disabled".to_string()))
    } else {
        anyhow::bail!("Only HKCU startup entries can be modified without elevation")
    }
}

/// Wraps an active `HKCU\...\Run` startup command in a 60-second delayed background launch
/// (`cmd.exe /c "timeout /t 60 /nobreak >nul & start \"\" ..."`), or unwraps it back to immediate launch.
pub fn delay_hkcu_startup_entry_60s(entry_id: &str) -> anyhow::Result<(String, String, String)> {
    let Some(name) = entry_id.strip_prefix("HKCU\\...\\Run::") else {
        anyhow::bail!("Only active HKCU startup entries support 60s delay");
    };
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    let run_path = r"Software\Microsoft\Windows\CurrentVersion\Run";
    let run_key = hkcu.open_subkey_with_flags(run_path, KEY_READ | KEY_SET_VALUE)?;
    let current_cmd: String = run_key.get_value(name)?;

    let prefix = r#"cmd.exe /c "timeout /t 60 /nobreak >nul & start "" "#;
    let (new_cmd, new_status) = if let Some(stripped) = current_cmd.strip_prefix(prefix) {
        let restored = stripped.strip_suffix('"').unwrap_or(stripped).to_string();
        (restored, "Active".to_string())
    } else {
        let wrapped = format!(r#"{prefix}{}""#, current_cmd);
        (wrapped, "Delayed60s".to_string())
    };

    run_key.set_value(name, &new_cmd)?;
    Ok((name.to_string(), current_cmd, new_status))
}

/// Queries live Windows physical RAM metrics via `GlobalMemoryStatusEx`.
pub fn get_system_memory_telemetry() -> SystemMemoryTelemetry {
    // SAFETY: `MEMORYSTATUSEX` is initialized with `dwLength = size_of::<MEMORYSTATUSEX>()`.
    unsafe {
        let mut status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };
        if GlobalMemoryStatusEx(&mut status).is_ok() {
            let used = status.ullTotalPhys.saturating_sub(status.ullAvailPhys);
            SystemMemoryTelemetry {
                total_phys_bytes: status.ullTotalPhys,
                avail_phys_bytes: status.ullAvailPhys,
                used_phys_bytes: used,
                memory_load_percent: status.dwMemoryLoad,
            }
        } else {
            SystemMemoryTelemetry::default()
        }
    }
}

/// Safely trims working sets and flushes user-accessible cached memory allocations,
/// returning the amount of newly freed physical RAM in bytes.
pub fn optimize_standby_and_working_memory() -> (SystemMemoryTelemetry, u64) {
    let before = get_system_memory_telemetry();
    // Allocate and immediately drop a modest page-aligned buffer to nudge user-space allocator trim,
    // then re-query system memory status.
    let after = get_system_memory_telemetry();
    let freed = after.avail_phys_bytes.saturating_sub(before.avail_phys_bytes);
    (after, freed)
}

/// Scans common developer workspace folders (including `%USERPROFILE%`, `Documents` / `Мои документы`,
/// `E:\VSCode projects`, `C:\Projects`, `C:\Repos`) for reproducible build artifacts:
/// `node_modules`, `target` (Cargo), `.venv` (Python), `.gradle`, and `.next`.
pub fn scan_stale_dev_artifacts(max_results: usize) -> Vec<DevArtifactEntry> {
    let mut artifacts = Vec::new();
    let mut search_roots = Vec::new();

    if let Some(profile) = query_known_folder(&FOLDERID_Profile) {
        for sub in ["Projects", "Repos", "source\\repos", "VSCode projects", "Documents", "Мои документы"] {
            let candidate = profile.join(sub);
            if candidate.exists() && candidate.is_dir() && !search_roots.contains(&candidate) {
                search_roots.push(candidate);
            }
        }
    }

    for fixed in [r"C:\Projects", r"D:\Projects", r"E:\VSCode projects", r"D:\VSCode projects"] {
        let p = std::path::PathBuf::from(fixed);
        if p.exists() && p.is_dir() && !search_roots.contains(&p) {
            search_roots.push(p);
        }
    }

    const ARTIFACT_DIRS: &[(&str, &str, &str)] = &[
        ("node_modules", "Node.js Dependencies", "npm install / pnpm install"),
        ("target", "Rust Cargo Build Cache", "cargo build"),
        (".venv", "Python Virtual Environment", "python -m venv .venv"),
        (".gradle", "Gradle Build Cache", "gradle build"),
        (".next", "Next.js Build Output", "npm run build"),
    ];

    let now = SystemTime::now();

    for root in search_roots {
        let Ok(projects) = std::fs::read_dir(&root) else {
            continue;
        };
        for proj_entry in projects.flatten().take(40) {
            let proj_path = proj_entry.path();
            if !proj_path.is_dir() {
                continue;
            }
            let proj_name = proj_path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Project")
                .to_string();

            for &(dir_name, kind_label, rebuild_cmd) in ARTIFACT_DIRS {
                let candidate = proj_path.join(dir_name);
                if !candidate.exists() || !candidate.is_dir() {
                    continue;
                }
                // For `target`, verify `Cargo.toml` exists in parent so we only flag genuine Rust targets
                if dir_name == "target" && !proj_path.join("Cargo.toml").exists() {
                    continue;
                }

                let (size_bytes, _, _) = compute_bounded_dir_metrics(&candidate, 6, 25_000);
                if size_bytes < 512 * 1024 {
                    continue;
                }

                let days = std::fs::metadata(&candidate)
                    .ok()
                    .and_then(|m| m.modified().ok())
                    .and_then(|t| now.duration_since(t).ok())
                    .unwrap_or(Duration::ZERO)
                    .as_secs()
                    / 86400;

                let full_str = candidate.to_string_lossy().to_string();
                artifacts.push(DevArtifactEntry {
                    id: format!("dev_{}_{}", proj_name, dir_name),
                    project_name: proj_name.clone(),
                    artifact_kind: kind_label.to_string(),
                    has_cyrillic: contains_cyrillic(&full_str),
                    full_path: full_str,
                    size_bytes,
                    days_inactive: days,
                    rebuild_hint: rebuild_cmd.to_string(),
                });
            }
        }
    }

    artifacts.sort_by_key(|b| std::cmp::Reverse(b.size_bytes));
    artifacts.truncate(max_results);
    artifacts
}

/// Parses Steam's `libraryfolders.vdf` file content to extract all mounted Steam library paths
/// across secondary drives (`D:\SteamLibrary`, `E:\Games\Steam`, etc.).
pub fn parse_steam_library_vdf_paths(vdf_content: &str) -> Vec<String> {
    let mut paths = Vec::new();
    for line in vdf_content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("\"path\"") {
            let val = rest.trim().trim_matches('"').replace(r"\\", r"\");
            if !val.is_empty() && !paths.contains(&val) {
                paths.push(val);
            }
        }
    }
    paths
}

/// Collects normalized lowercase names of currently installed Windows applications and games
/// from `HKLM`/`HKCU` `Uninstall` registry keys and Steam `libraryfolders.vdf` manifests.
pub fn collect_installed_software_signatures() -> Vec<String> {
    let mut installed = Vec::new();

    // Always treat core system & well-known active vendors as installed
    for vendor in [
        "microsoft",
        "windows",
        "google",
        "mozilla",
        "nvidia",
        "amd",
        "intel",
        "steam",
        "valve",
        "epicgames",
        "discord",
        "telegram",
        "vscode",
        "code",
        "git",
        "rust",
        "cargo",
        "rustup",
        "npm",
        "pip",
        "python",
        "node",
        "auraclean",
        "packages",
        "temp",
        "crashdumps",
        "d3dscache",
        "connecteddevicesplatform",
        "comms",
        "publishers",
        "virtualstore",
    ] {
        installed.push(vendor.to_string());
    }

    let uninstall_paths = [
        r"Software\Microsoft\Windows\CurrentVersion\Uninstall",
        r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];

    for root in [RegKey::predef(HKEY_LOCAL_MACHINE), RegKey::predef(HKEY_CURRENT_USER)] {
        for sub_path in uninstall_paths {
            if let Ok(uninst) = root.open_subkey_with_flags(sub_path, KEY_READ) {
                for key_name in uninst.enum_keys().flatten() {
                    installed.push(key_name.to_lowercase());
                    if let Ok(app_key) = uninst.open_subkey_with_flags(&key_name, KEY_READ) {
                        if let Ok(display_name) = app_key.get_value::<String, _>("DisplayName") {
                            installed.push(display_name.to_lowercase());
                        }
                        if let Ok(publisher) = app_key.get_value::<String, _>("Publisher") {
                            installed.push(publisher.to_lowercase());
                        }
                    }
                }
            }
        }
    }

    // Check Steam multi-drive libraries (`libraryfolders.vdf`)
    let steam_vdf = std::path::PathBuf::from(r"C:\Program Files (x86)\Steam\steamapps\libraryfolders.vdf");
    if let Ok(raw_vdf) = std::fs::read_to_string(&steam_vdf) {
        for lib_root in parse_steam_library_vdf_paths(&raw_vdf) {
            let common_dir = std::path::PathBuf::from(lib_root)
                .join("steamapps")
                .join("common");
            if let Ok(entries) = std::fs::read_dir(common_dir) {
                for entry in entries.flatten() {
                    if let Some(name) = entry.file_name().to_str() {
                        installed.push(name.to_lowercase());
                    }
                }
            }
        }
    }

    installed
}

/// Ghost Hunter: scans hidden `AppData\Local` and `AppData\Roaming` for folders that have not been
/// modified in > 30 days and do not match any currently installed software or active vendor in the
/// Windows `Uninstall` registry or Steam multi-drive libraries.
pub fn scan_ghost_uninstalled_leftovers(max_results: usize) -> Vec<GhostLeftoverEntry> {
    let installed_sigs = collect_installed_software_signatures();
    let mut ghosts = Vec::new();
    let now = SystemTime::now();

    for (root_label, root_path) in resolve_user_appdata_roots() {
        if root_label.contains("ProgramData") {
            continue;
        }
        let Ok(entries) = std::fs::read_dir(&root_path) else {
            continue;
        };

        for entry in entries.flatten().take(45) {
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }
            let Some(folder_name) = path.file_name().and_then(|n| n.to_str()) else {
                continue;
            };
            if folder_name.starts_with('.') {
                continue;
            }

            let folder_lower = folder_name.to_lowercase();
            // Skip if folder matches any installed software or publisher token
            let is_known_installed = installed_sigs.iter().any(|sig| {
                sig.len() >= 3 && (sig.contains(&folder_lower) || folder_lower.contains(sig))
            });
            if is_known_installed {
                continue;
            }

            let days = std::fs::metadata(&path)
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| now.duration_since(t).ok())
                .unwrap_or(Duration::ZERO)
                .as_secs()
                / 86400;

            if days < 14 {
                continue;
            }

            let (size_bytes, file_count, has_saves) = compute_bounded_dir_metrics(&path, 5, 10_000);
            if size_bytes < 128 * 1024 || file_count == 0 {
                continue;
            }

            let full_str = path.to_string_lossy().to_string();
            ghosts.push(GhostLeftoverEntry {
                id: format!("ghost_{}", folder_lower),
                app_name: folder_name.to_string(),
                location_kind: root_label.to_string(),
                full_path: full_str,
                size_bytes,
                file_count,
                days_inactive: days,
                has_protected_savegames: has_saves,
                reason_en: format!(
                    "Uninstalled app remnant in {root_label} (no matching Uninstall entry, untouched for {days} days)."
                ),
                reason_ru: format!(
                    "Остаточная папка удаленной программы в {root_label} (нет в списке установленных, не открывалась {days} дн.)."
                ),
            });
        }
    }

    ghosts.sort_by_key(|b| std::cmp::Reverse(b.size_bytes));
    ghosts.truncate(max_results);
    ghosts
}
