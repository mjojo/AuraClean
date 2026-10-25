#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]
//! AuraClean Native 1-Click Desktop Application (`AuraClean.exe`).
//!
//! Launches a Windows 11 Mica/Dark Cyber-Fluent UI powered by the native OS Edge WebView2
//! engine, connected to the AuraClean `core-engine` and `safety-guard` Time-Capsule Vault.
//!
//! Architected and maintained by mjojo (https://github.com/mjojo/AuraClean).

use anyhow::Result;
use core_engine::{
    CleaningRule, DeepFolderInsight, DevArtifactEntry, GhostLeftoverEntry, RegistryFinding,
    SpaceLensFileEntry, StartupEntry, SystemMemoryTelemetry, delay_hkcu_startup_entry_60s,
    get_system_memory_telemetry, load_rules_from_dir, optimize_standby_and_working_memory,
    resolve_base_directories, scan_directory_with_rule, scan_ghost_uninstalled_leftovers,
    scan_hidden_appdata_and_documents, scan_safe_registry_zones, scan_space_lens_top_files,
    scan_stale_dev_artifacts, scan_startup_entries, toggle_hkcu_startup_entry,
};
use ipc_protocol::{Locale, ScannedItem, VaultTransactionSummary};
use safety_guard::{
    QuarantineCandidate, RegistrySnapshotEntry, TimeCapsuleVault, VaultConfig,
    evaluate_path_whitelist, is_file_exclusively_openable,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tao::{
    dpi::LogicalSize,
    event::{Event, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder, EventLoopProxy},
    window::WindowBuilder,
};
use uuid::Uuid;
use wry::WebViewBuilder;

const EMBEDDED_HTML: &str = include_str!("../ui/index.html");

#[derive(Debug, Clone)]
enum UserEvent {
    BackendUpdated {
        state_json: String,
        toast: Option<String>,
    },
}

#[derive(Debug, Deserialize)]
struct UiIpcMessage {
    cmd: String,
    #[serde(default)]
    lang: String,
    #[serde(default)]
    tx_id: Option<String>,
    #[serde(default)]
    approved_rule_ids: Vec<String>,
    #[serde(default)]
    include_registry: bool,
    #[serde(default)]
    target_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RuleUiView {
    id: String,
    category: String,
    safety_level: String,
    quarantine_tier: String,
    name_en: String,
    desc_en: String,
    name_ru: String,
    desc_ru: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    scanned_count: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scanned_bytes: Option<u64>,
    #[serde(default)]
    sample_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ScanUiSummary {
    total_items: usize,
    total_bytes: u64,
    rules_bytes: u64,
    dev_bytes: u64,
    ghost_bytes: u64,
    total_shielded: usize,
    registry_count: usize,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct FrontendState {
    rules: Vec<RuleUiView>,
    registry_findings: Vec<RegistryFinding>,
    deep_folders: Vec<DeepFolderInsight>,
    space_lens_files: Vec<SpaceLensFileEntry>,
    startup_entries: Vec<StartupEntry>,
    dev_artifacts: Vec<DevArtifactEntry>,
    ghost_leftovers: Vec<GhostLeftoverEntry>,
    memory_telemetry: SystemMemoryTelemetry,
    scan_results: Option<ScanUiSummary>,
    transactions: Vec<VaultTransactionSummary>,
    vault_bytes: u64,
}

struct SharedAppState {
    rules: Vec<CleaningRule>,
    last_scanned_items: Vec<ScannedItem>,
    last_registry_findings: Vec<RegistryFinding>,
    frontend_state: FrontendState,
    vault_dir: PathBuf,
}

fn default_vault_dir() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("AuraClean")
        .join("Vault")
}

fn build_rule_views(rules: &[CleaningRule]) -> Vec<RuleUiView> {
    rules
        .iter()
        .map(|r| {
            let en = r.localized(Locale::En);
            let ru = r.localized(Locale::Ru);
            RuleUiView {
                id: r.id.clone(),
                category: r.category.clone(),
                safety_level: format!("{:?}", r.safety_level),
                quarantine_tier: format!("{:?}", r.quarantine_tier),
                name_en: en.name,
                desc_en: en.description,
                name_ru: ru.name,
                desc_ru: ru.description,
                scanned_count: None,
                scanned_bytes: None,
                sample_paths: Vec::new(),
            }
        })
        .collect()
}

fn main() -> Result<()> {
    let vault_dir = default_vault_dir();
    let rules = load_rules_from_dir(std::path::Path::new("rules"))?;
    let vault = TimeCapsuleVault::open(VaultConfig::new(&vault_dir))?;

    let initial_frontend = FrontendState {
        rules: build_rule_views(&rules),
        registry_findings: Vec::new(),
        deep_folders: Vec::new(),
        space_lens_files: Vec::new(),
        startup_entries: scan_startup_entries(),
        dev_artifacts: Vec::new(),
        ghost_leftovers: Vec::new(),
        memory_telemetry: get_system_memory_telemetry(),
        scan_results: None,
        transactions: vault.list_transactions().unwrap_or_default(),
        vault_bytes: vault.current_vault_footprint_bytes().unwrap_or(0),
    };

    let init_script = format!(
        "window.__AURACLEAN_INITIAL_STATE__ = {};",
        serde_json::to_string(&initial_frontend)?
    );

    let shared = Arc::new(Mutex::new(SharedAppState {
        rules,
        last_scanned_items: Vec::new(),
        last_registry_findings: Vec::new(),
        frontend_state: initial_frontend,
        vault_dir,
    }));

    let event_loop = EventLoopBuilder::<UserEvent>::with_user_event().build();
    let proxy: EventLoopProxy<UserEvent> = event_loop.create_proxy();

    let window = WindowBuilder::new()
        .with_title("AuraClean by mjojo — Hyper-Safe Windows Maintenance Suite")
        .with_inner_size(LogicalSize::new(1120.0, 740.0))
        .with_min_inner_size(LogicalSize::new(920.0, 620.0))
        .build(&event_loop)?;

    // Apply native Windows 11 Mica / Acrylic vibrancy when supported by the OS build
    let _ = window_vibrancy::apply_mica(&window, Some(true))
        .or_else(|_| window_vibrancy::apply_acrylic(&window, Some((11, 11, 20, 210))));

    let shared_for_ipc = Arc::clone(&shared);
    let proxy_for_ipc = proxy.clone();

    let webview = WebViewBuilder::new()
        .with_initialization_script(&init_script)
        .with_html(EMBEDDED_HTML)
        .with_ipc_handler(move |req| {
            let body = req.body().to_string();
            let shared_clone = Arc::clone(&shared_for_ipc);
            let proxy_clone = proxy_for_ipc.clone();

            std::thread::spawn(move || {
                if let Ok(msg) = serde_json::from_str::<UiIpcMessage>(&body) {
                    handle_ui_command(msg, &shared_clone, &proxy_clone);
                }
            });
        })
        .build(&window)?;

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;

        match event {
            Event::WindowEvent {
                event: WindowEvent::CloseRequested,
                ..
            } => {
                *control_flow = ControlFlow::Exit;
            }
            Event::UserEvent(UserEvent::BackendUpdated { state_json, toast }) => {
                let toast_arg = match toast {
                    Some(t) => serde_json::to_string(&t).unwrap_or_else(|_| "null".to_string()),
                    None => "null".to_string(),
                };
                let js = format!("window.__onBackendStateUpdate({state_json}, {toast_arg});");
                let _ = webview.evaluate_script(&js);
            }
            _ => {}
        }
    });
}

fn handle_ui_command(
    msg: UiIpcMessage,
    shared: &Arc<Mutex<SharedAppState>>,
    proxy: &EventLoopProxy<UserEvent>,
) {
    let locale = Locale::from_code(&msg.lang);

    match msg.cmd.as_str() {
        "scan" => {
            let (rules, vault_dir) = {
                let guard = shared.lock().unwrap();
                (guard.rules.clone(), guard.vault_dir.clone())
            };

            let mut all_items = Vec::new();
            let mut total_bytes = 0u64;
            let mut total_shielded = 0usize;
            let mut updated_views = build_rule_views(&rules);

            for (idx, rule) in rules.iter().enumerate() {
                let dirs = resolve_base_directories(rule);
                let mut rule_count = 0usize;
                let mut rule_bytes = 0u64;
                let mut samples = Vec::new();

                for dir in dirs {
                    let rep = scan_directory_with_rule(&dir, rule, locale, 50_000);
                    rule_count += rep.items.len();
                    rule_bytes += rep.total_reclaimable_bytes();
                    total_shielded += rep.skipped_locked
                        + rep.skipped_cloud
                        + rep.skipped_recent
                        + rep.skipped_whitelisted;
                    for item in &rep.items {
                        if samples.len() < 3 {
                            samples.push(item.path.to_string_lossy().to_string());
                        }
                    }
                    all_items.extend(rep.items);
                }

                total_bytes += rule_bytes;
                updated_views[idx].scanned_count = Some(rule_count);
                updated_views[idx].scanned_bytes = Some(rule_bytes);
                updated_views[idx].sample_paths = samples;
            }

            let reg_findings = scan_safe_registry_zones(50);
            let deep_folders = scan_hidden_appdata_and_documents(30);
            let space_lens_files = scan_space_lens_top_files(5 * 1024 * 1024, 25);
            let startup_entries = scan_startup_entries();
            let dev_artifacts = scan_stale_dev_artifacts(25);
            let ghost_leftovers = scan_ghost_uninstalled_leftovers(25);
            let memory_telemetry = get_system_memory_telemetry();

            let dev_bytes: u64 = dev_artifacts.iter().map(|d| d.size_bytes).sum();
            let ghost_bytes: u64 = ghost_leftovers
                .iter()
                .filter(|g| !g.has_protected_savegames)
                .map(|g| g.size_bytes)
                .sum();
            let combined_reclaimable = total_bytes
                .saturating_add(dev_bytes)
                .saturating_add(ghost_bytes);

            let vault = TimeCapsuleVault::open(VaultConfig::new(&vault_dir)).ok();
            let mut guard = shared.lock().unwrap();
            guard.frontend_state.rules = updated_views;
            guard.frontend_state.registry_findings = reg_findings.clone();
            guard.frontend_state.deep_folders = deep_folders;
            guard.frontend_state.space_lens_files = space_lens_files;
            guard.frontend_state.startup_entries = startup_entries;
            guard.frontend_state.dev_artifacts = dev_artifacts;
            guard.frontend_state.ghost_leftovers = ghost_leftovers;
            guard.frontend_state.memory_telemetry = memory_telemetry;
            guard.frontend_state.scan_results = Some(ScanUiSummary {
                total_items: all_items.len(),
                total_bytes: combined_reclaimable,
                rules_bytes: total_bytes,
                dev_bytes,
                ghost_bytes,
                total_shielded,
                registry_count: reg_findings.len(),
            });
            if let Some(v) = vault {
                guard.frontend_state.transactions = v.list_transactions().unwrap_or_default();
                guard.frontend_state.vault_bytes = v.current_vault_footprint_bytes().unwrap_or(0);
            }
            guard.last_scanned_items = all_items;
            guard.last_registry_findings = reg_findings;

            let toast = match locale {
                Locale::En => format!(
                    "Smart Scan finished: {} safe files & {} registry orphans found ({} shielded)",
                    guard
                        .frontend_state
                        .scan_results
                        .as_ref()
                        .map(|s| s.total_items)
                        .unwrap_or(0),
                    guard.last_registry_findings.len(),
                    total_shielded
                ),
                Locale::Ru => format!(
                    "Анализ завершен: {} файлов и {} сирот реестра (защищено щитами: {})",
                    guard
                        .frontend_state
                        .scan_results
                        .as_ref()
                        .map(|s| s.total_items)
                        .unwrap_or(0),
                    guard.last_registry_findings.len(),
                    total_shielded
                ),
            };

            if let Ok(state_json) = serde_json::to_string(&guard.frontend_state) {
                let _ = proxy.send_event(UserEvent::BackendUpdated {
                    state_json,
                    toast: Some(toast),
                });
            }
        }
        "confirm_quarantine" => {
            if msg.approved_rule_ids.is_empty() && !msg.include_registry {
                return;
            }

            let (candidates, reg_snapshots, vault_dir) = {
                let guard = shared.lock().unwrap();
                let cands: Vec<QuarantineCandidate> = guard
                    .last_scanned_items
                    .iter()
                    .filter(|item| msg.approved_rule_ids.contains(&item.rule_id))
                    .take(50)
                    .map(|item| QuarantineCandidate {
                        rule_id: item.rule_id.clone(),
                        path: item.path.clone(),
                        requested_tier: item.quarantine_tier,
                    })
                    .collect();

                let regs: Vec<RegistrySnapshotEntry> = if msg.include_registry {
                    guard
                        .last_registry_findings
                        .iter()
                        .map(|rf| RegistrySnapshotEntry {
                            root_hive: rf.root_hive.clone(),
                            subkey_path: rf.subkey_path.clone(),
                            value_name: Some(rf.value_name.clone()),
                            value_type: "REG_SZ".to_string(),
                            value_data: rf.raw_value_data.clone(),
                            human_reason: rf.reason_en.clone(),
                        })
                        .collect()
                } else {
                    Vec::new()
                };

                (cands, regs, guard.vault_dir.clone())
            };

            if candidates.is_empty() && reg_snapshots.is_empty() {
                return;
            }

            if let Ok(vault) = TimeCapsuleVault::open(VaultConfig::new(&vault_dir))
                && let Ok(tx_summary) = vault.quarantine_batch(&candidates, &reg_snapshots)
            {
                let mut guard = shared.lock().unwrap();
                guard
                    .last_scanned_items
                    .retain(|i| !msg.approved_rule_ids.contains(&i.rule_id));
                if msg.include_registry {
                    guard.last_registry_findings.clear();
                    guard.frontend_state.registry_findings.clear();
                }

                let remaining_rules_bytes: u64 =
                    guard.last_scanned_items.iter().map(|i| i.size_bytes).sum();
                let dev_bytes: u64 = guard
                    .frontend_state
                    .dev_artifacts
                    .iter()
                    .map(|d| d.size_bytes)
                    .sum();
                let ghost_bytes: u64 = guard
                    .frontend_state
                    .ghost_leftovers
                    .iter()
                    .filter(|g| !g.has_protected_savegames)
                    .map(|g| g.size_bytes)
                    .sum();
                let combined_bytes = remaining_rules_bytes
                    .saturating_add(dev_bytes)
                    .saturating_add(ghost_bytes);
                let prev_shielded = guard
                    .frontend_state
                    .scan_results
                    .as_ref()
                    .map(|s| s.total_shielded)
                    .unwrap_or(0);

                for rv in &mut guard.frontend_state.rules {
                    if msg.approved_rule_ids.contains(&rv.id) {
                        rv.scanned_count = Some(0);
                        rv.scanned_bytes = Some(0);
                        rv.sample_paths.clear();
                    }
                }

                guard.frontend_state.scan_results = Some(ScanUiSummary {
                    total_items: guard.last_scanned_items.len(),
                    total_bytes: combined_bytes,
                    rules_bytes: remaining_rules_bytes,
                    dev_bytes,
                    ghost_bytes,
                    total_shielded: prev_shielded,
                    registry_count: guard.last_registry_findings.len(),
                });
                guard.frontend_state.transactions = vault.list_transactions().unwrap_or_default();
                guard.frontend_state.vault_bytes =
                    vault.current_vault_footprint_bytes().unwrap_or(0);

                let toast = match locale {
                    Locale::En => format!(
                        "Permission verified: Transaction {} saved to Time-Capsule Vault",
                        &tx_summary.transaction_id.to_string()[..8]
                    ),
                    Locale::Ru => format!(
                        "Разрешение подтверждено: транзакция {} сохранена в Капсулу Времени",
                        &tx_summary.transaction_id.to_string()[..8]
                    ),
                };

                if let Ok(state_json) = serde_json::to_string(&guard.frontend_state) {
                    let _ = proxy.send_event(UserEvent::BackendUpdated {
                        state_json,
                        toast: Some(toast),
                    });
                }
            }
        }
        "restore_tx" => {
            let Some(tx_id_str) = msg.tx_id else {
                return;
            };
            let Ok(tx_uuid) = Uuid::parse_str(&tx_id_str) else {
                return;
            };

            let vault_dir = { shared.lock().unwrap().vault_dir.clone() };
            if let Ok(vault) = TimeCapsuleVault::open(VaultConfig::new(&vault_dir))
                && let Ok((restored_count, _)) = vault.restore_transaction(tx_uuid)
            {
                let mut guard = shared.lock().unwrap();
                guard.frontend_state.transactions = vault.list_transactions().unwrap_or_default();
                guard.frontend_state.vault_bytes =
                    vault.current_vault_footprint_bytes().unwrap_or(0);

                let toast = match locale {
                    Locale::En => format!(
                        "Restored {restored_count} files from transaction {}",
                        &tx_id_str[..8]
                    ),
                    Locale::Ru => format!(
                        "Восстановлено {restored_count} файлов из транзакции {}",
                        &tx_id_str[..8]
                    ),
                };

                if let Ok(state_json) = serde_json::to_string(&guard.frontend_state) {
                    let _ = proxy.send_event(UserEvent::BackendUpdated {
                        state_json,
                        toast: Some(toast),
                    });
                }
            }
        }
        "boost_ram" => {
            let (telemetry, freed_bytes) = optimize_standby_and_working_memory();
            let mut guard = shared.lock().unwrap();
            guard.frontend_state.memory_telemetry = telemetry;
            let freed_mb = freed_bytes / (1024 * 1024);
            let toast = match locale {
                Locale::En => format!(
                    "RAM Standby & Working Set optimized (Load: {}%, Freed: ~{} MB)",
                    guard.frontend_state.memory_telemetry.memory_load_percent, freed_mb
                ),
                Locale::Ru => format!(
                    "ОЗУ оптимизирована перед запуском игры (Загрузка: {}%, Освобождено: ~{} МБ)",
                    guard.frontend_state.memory_telemetry.memory_load_percent, freed_mb
                ),
            };
            if let Ok(state_json) = serde_json::to_string(&guard.frontend_state) {
                let _ = proxy.send_event(UserEvent::BackendUpdated {
                    state_json,
                    toast: Some(toast),
                });
            }
        }
        "boot_hydrate" => {
            let deep_folders = scan_hidden_appdata_and_documents(25);
            let dev_artifacts = scan_stale_dev_artifacts(20);
            let memory_telemetry = get_system_memory_telemetry();
            let mut guard = shared.lock().unwrap();
            guard.frontend_state.deep_folders = deep_folders;
            guard.frontend_state.dev_artifacts = dev_artifacts;
            guard.frontend_state.memory_telemetry = memory_telemetry;
            if let Ok(state_json) = serde_json::to_string(&guard.frontend_state) {
                let _ = proxy.send_event(UserEvent::BackendUpdated {
                    state_json,
                    toast: None,
                });
            }
        }
        "clean_single_ghost" => {
            let Some(ref target_id) = msg.target_id else {
                return;
            };
            let (maybe_ghost, vault_dir) = {
                let guard = shared.lock().unwrap();
                let found = guard
                    .frontend_state
                    .ghost_leftovers
                    .iter()
                    .find(|g| &g.id == target_id && !g.has_protected_savegames)
                    .cloned();
                (found, guard.vault_dir.clone())
            };
            let Some(ghost) = maybe_ghost else {
                return;
            };

            let mut cands = Vec::new();
            for entry in jwalk::WalkDir::new(&ghost.full_path)
                .follow_links(false)
                .skip_hidden(false)
                .max_depth(4)
                .into_iter()
                .flatten()
                .take(250)
            {
                if entry.file_type().is_file() {
                    cands.push(QuarantineCandidate {
                        rule_id: ghost.id.clone(),
                        path: entry.path(),
                        requested_tier: ipc_protocol::QuarantineTier::ArchiveToVault,
                    });
                }
            }

            if let Ok(vault) = TimeCapsuleVault::open(VaultConfig::new(&vault_dir))
                && let Ok(tx_summary) = vault.quarantine_batch(&cands, &[])
            {
                let mut guard = shared.lock().unwrap();
                guard
                    .frontend_state
                    .ghost_leftovers
                    .retain(|g| &g.id != target_id);
                guard.frontend_state.transactions = vault.list_transactions().unwrap_or_default();
                guard.frontend_state.vault_bytes =
                    vault.current_vault_footprint_bytes().unwrap_or(0);
                recompute_scan_summary(&mut guard);

                let toast = match locale {
                    Locale::En => format!(
                        "Ghost folder '{}' moved to Time-Capsule (tx {})",
                        ghost.app_name,
                        &tx_summary.transaction_id.to_string()[..8]
                    ),
                    Locale::Ru => format!(
                        "Остатки «{}» перенесены в Капсулу Времени (транзакция {})",
                        ghost.app_name,
                        &tx_summary.transaction_id.to_string()[..8]
                    ),
                };
                if let Ok(state_json) = serde_json::to_string(&guard.frontend_state) {
                    let _ = proxy.send_event(UserEvent::BackendUpdated {
                        state_json,
                        toast: Some(toast),
                    });
                }
            }
        }
        "clean_single_dev" => {
            let Some(ref target_id) = msg.target_id else {
                return;
            };
            let (maybe_dev, vault_dir) = {
                let guard = shared.lock().unwrap();
                let found = guard
                    .frontend_state
                    .dev_artifacts
                    .iter()
                    .find(|d| &d.id == target_id)
                    .cloned();
                (found, guard.vault_dir.clone())
            };
            let Some(dev) = maybe_dev else {
                return;
            };

            let target_path = PathBuf::from(&dev.full_path);
            if evaluate_path_whitelist(&target_path).is_allowed() && target_path.exists() {
                // Reproducible dev artifacts (`node_modules`, `target`, `.venv`, `.gradle`) are deleted directly
                // without archiving gigabytes into Time-Capsule Vault.
                let _ = std::fs::remove_dir_all(&target_path);

                let vault = TimeCapsuleVault::open(VaultConfig::new(&vault_dir)).ok();
                let mut guard = shared.lock().unwrap();
                guard
                    .frontend_state
                    .dev_artifacts
                    .retain(|d| &d.id != target_id);
                if let Some(v) = vault {
                    guard.frontend_state.transactions = v.list_transactions().unwrap_or_default();
                    guard.frontend_state.vault_bytes =
                        v.current_vault_footprint_bytes().unwrap_or(0);
                }
                recompute_scan_summary(&mut guard);

                let toast = match locale {
                    Locale::En => format!(
                        "Directly deleted '{}' ({}) — rebuild anytime via `{}`",
                        dev.project_name, dev.artifact_kind, dev.rebuild_hint
                    ),
                    Locale::Ru => format!(
                        "Напрямую удалена сборка «{}» ({}) — пересобирается через `{}`",
                        dev.project_name, dev.artifact_kind, dev.rebuild_hint
                    ),
                };
                if let Ok(state_json) = serde_json::to_string(&guard.frontend_state) {
                    let _ = proxy.send_event(UserEvent::BackendUpdated {
                        state_json,
                        toast: Some(toast),
                    });
                }
            }
        }
        "clean_single_registry" => {
            let Some(ref target_id) = msg.target_id else {
                return;
            };
            let (maybe_reg, vault_dir) = {
                let guard = shared.lock().unwrap();
                let found = guard
                    .last_registry_findings
                    .iter()
                    .find(|r| r.finding_id.to_string() == *target_id)
                    .cloned();
                (found, guard.vault_dir.clone())
            };
            let Some(rf) = maybe_reg else {
                return;
            };

            let snap = RegistrySnapshotEntry {
                root_hive: rf.root_hive.clone(),
                subkey_path: rf.subkey_path.clone(),
                value_name: Some(rf.value_name.clone()),
                value_type: "REG_SZ".to_string(),
                value_data: rf.raw_value_data.clone(),
                human_reason: rf.reason_en.clone(),
            };

            if let Ok(vault) = TimeCapsuleVault::open(VaultConfig::new(&vault_dir))
                && let Ok(tx_summary) = vault.quarantine_batch(&[], &[snap])
            {
                let mut guard = shared.lock().unwrap();
                guard
                    .last_registry_findings
                    .retain(|r| r.finding_id.to_string() != *target_id);
                guard
                    .frontend_state
                    .registry_findings
                    .retain(|r| r.finding_id.to_string() != *target_id);
                guard.frontend_state.transactions = vault.list_transactions().unwrap_or_default();
                guard.frontend_state.vault_bytes =
                    vault.current_vault_footprint_bytes().unwrap_or(0);
                recompute_scan_summary(&mut guard);

                let toast = match locale {
                    Locale::En => format!(
                        "Registry key backed up to Time-Capsule (.reg snapshot {})",
                        &tx_summary.transaction_id.to_string()[..8]
                    ),
                    Locale::Ru => format!(
                        "Ключ реестра сохранен в снимок .reg Time-Capsule ({})",
                        &tx_summary.transaction_id.to_string()[..8]
                    ),
                };
                if let Ok(state_json) = serde_json::to_string(&guard.frontend_state) {
                    let _ = proxy.send_event(UserEvent::BackendUpdated {
                        state_json,
                        toast: Some(toast),
                    });
                }
            }
        }
        "open_in_explorer" => {
            let Some(ref target_path) = msg.target_id else {
                return;
            };
            let p = PathBuf::from(target_path);
            if p.exists() {
                if p.is_file() {
                    let _ = std::process::Command::new("explorer.exe")
                        .arg(format!("/select,{}", p.display()))
                        .spawn();
                } else {
                    let _ = std::process::Command::new("explorer.exe")
                        .arg(p.as_os_str())
                        .spawn();
                }
            }
        }
        "delete_space_lens_file" => {
            let Some(ref target_path) = msg.target_id else {
                return;
            };
            let p = PathBuf::from(target_path);
            if evaluate_path_whitelist(&p).is_allowed()
                && p.exists()
                && p.is_file()
                && is_file_exclusively_openable(&p)
                && std::fs::remove_file(&p).is_ok()
            {
                let mut guard = shared.lock().unwrap();
                guard
                    .frontend_state
                    .space_lens_files
                    .retain(|f| &f.full_path != target_path);

                let toast = match locale {
                    Locale::En => format!("Deleted large file: {}", p.display()),
                    Locale::Ru => format!("Удален крупный файл: {}", p.display()),
                };
                if let Ok(state_json) = serde_json::to_string(&guard.frontend_state) {
                    let _ = proxy.send_event(UserEvent::BackendUpdated {
                        state_json,
                        toast: Some(toast),
                    });
                }
            }
        }
        "toggle_startup" => {
            let Some(ref entry_id) = msg.target_id else {
                return;
            };
            let vault_dir = { shared.lock().unwrap().vault_dir.clone() };
            if let Ok((name, orig_cmd, new_status)) = toggle_hkcu_startup_entry(entry_id) {
                let snap = RegistrySnapshotEntry {
                    root_hive: "HKEY_CURRENT_USER".to_string(),
                    subkey_path: r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
                    value_name: Some(name.clone()),
                    value_type: "REG_SZ".to_string(),
                    value_data: orig_cmd,
                    human_reason: format!("Startup entry '{name}' toggled to {new_status}"),
                };
                if let Ok(vault) = TimeCapsuleVault::open(VaultConfig::new(&vault_dir)) {
                    let _ = vault.quarantine_batch(&[], &[snap]);
                }

                let updated_startup = scan_startup_entries();
                let vault = TimeCapsuleVault::open(VaultConfig::new(&vault_dir)).ok();
                let mut guard = shared.lock().unwrap();
                guard.frontend_state.startup_entries = updated_startup;
                if let Some(v) = vault {
                    guard.frontend_state.transactions = v.list_transactions().unwrap_or_default();
                    guard.frontend_state.vault_bytes =
                        v.current_vault_footprint_bytes().unwrap_or(0);
                }

                let toast = match locale {
                    Locale::En => format!(
                        "Startup '{}' is now {} (backed up in Time-Capsule)",
                        name, new_status
                    ),
                    Locale::Ru => format!(
                        "Автозапуск «{}» переведен в режим {} (снимок в Time-Capsule)",
                        name, new_status
                    ),
                };
                if let Ok(state_json) = serde_json::to_string(&guard.frontend_state) {
                    let _ = proxy.send_event(UserEvent::BackendUpdated {
                        state_json,
                        toast: Some(toast),
                    });
                }
            }
        }
        "delay_startup_60s" => {
            let Some(ref entry_id) = msg.target_id else {
                return;
            };
            let vault_dir = { shared.lock().unwrap().vault_dir.clone() };
            if let Ok((name, orig_cmd, new_status)) = delay_hkcu_startup_entry_60s(entry_id) {
                let snap = RegistrySnapshotEntry {
                    root_hive: "HKEY_CURRENT_USER".to_string(),
                    subkey_path: r"Software\Microsoft\Windows\CurrentVersion\Run".to_string(),
                    value_name: Some(name.clone()),
                    value_type: "REG_SZ".to_string(),
                    value_data: orig_cmd,
                    human_reason: format!("Startup entry '{name}' set to {new_status}"),
                };
                if let Ok(vault) = TimeCapsuleVault::open(VaultConfig::new(&vault_dir)) {
                    let _ = vault.quarantine_batch(&[], &[snap]);
                }

                let updated_startup = scan_startup_entries();
                let vault = TimeCapsuleVault::open(VaultConfig::new(&vault_dir)).ok();
                let mut guard = shared.lock().unwrap();
                guard.frontend_state.startup_entries = updated_startup;
                if let Some(v) = vault {
                    guard.frontend_state.transactions = v.list_transactions().unwrap_or_default();
                    guard.frontend_state.vault_bytes =
                        v.current_vault_footprint_bytes().unwrap_or(0);
                }

                let toast = match locale {
                    Locale::En => format!(
                        "Startup '{}' set to {} (backed up in Time-Capsule)",
                        name, new_status
                    ),
                    Locale::Ru => format!(
                        "Автозапуск «{}» переведен в режим {} (снимок в Time-Capsule)",
                        name, new_status
                    ),
                };
                if let Ok(state_json) = serde_json::to_string(&guard.frontend_state) {
                    let _ = proxy.send_event(UserEvent::BackendUpdated {
                        state_json,
                        toast: Some(toast),
                    });
                }
            }
        }
        _ => {}
    }
}

fn recompute_scan_summary(guard: &mut SharedAppState) {
    let rules_bytes: u64 = guard.last_scanned_items.iter().map(|i| i.size_bytes).sum();
    let dev_bytes: u64 = guard
        .frontend_state
        .dev_artifacts
        .iter()
        .map(|d| d.size_bytes)
        .sum();
    let ghost_bytes: u64 = guard
        .frontend_state
        .ghost_leftovers
        .iter()
        .filter(|g| !g.has_protected_savegames)
        .map(|g| g.size_bytes)
        .sum();
    let prev_shielded = guard
        .frontend_state
        .scan_results
        .as_ref()
        .map(|s| s.total_shielded)
        .unwrap_or(0);

    guard.frontend_state.scan_results = Some(ScanUiSummary {
        total_items: guard.last_scanned_items.len(),
        total_bytes: rules_bytes
            .saturating_add(dev_bytes)
            .saturating_add(ghost_bytes),
        rules_bytes,
        dev_bytes,
        ghost_bytes,
        total_shielded: prev_shielded,
        registry_count: guard.last_registry_findings.len(),
    });
}
