//! AuraClean `core-engine` — Declarative Multilingual Rule Parser & Safe Scanner.
//!
//! Designed and maintained by mjojo (https://github.com/mjojo/AuraClean).

pub mod registry_inspector;

pub use registry_inspector::{
    RegistryFinding, RegistryZone, extract_executable_path_from_registry_string,
    is_on_mounted_fixed_drive, scan_safe_registry_zones, verify_orphaned_executable,
};

use anyhow::{Context, Result, bail};
use ipc_protocol::{Locale, LocalizedText, QuarantineTier, SafetyLevel, ScannedItem};
use safety_guard::{
    AttributeSafetyVerdict, evaluate_path_whitelist, inspect_path_attributes,
    is_file_exclusively_openable, is_older_than_threshold, validate_rule_pattern_safety,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;
use uuid::Uuid;

/// Declarative TOML rule file container (`rules/*.toml`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleCatalogFile {
    pub schema_version: u32,
    pub category: String,
    #[serde(default)]
    pub rule: Vec<CleaningRule>,
}

/// Single declarative cleaning rule with embedded multilingual explanations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CleaningRule {
    pub id: String,
    pub category: String,
    pub safety_level: SafetyLevel,
    #[serde(default)]
    pub quarantine_tier: QuarantineTier,
    #[serde(default)]
    pub detect_processes: Vec<String>,
    #[serde(default = "default_min_age_hours")]
    pub min_age_hours: u64,
    pub paths: Vec<String>,
    #[serde(default)]
    pub exclude_patterns: Vec<String>,
    pub i18n: HashMap<String, LocalizedText>,
}

const fn default_min_age_hours() -> u64 {
    24
}

impl CleaningRule {
    /// Returns the localized title and explanation for the requested UI language,
    /// falling back to English (`en`) if the requested language is unavailable.
    pub fn localized(&self, locale: Locale) -> LocalizedText {
        self.i18n
            .get(locale.code())
            .or_else(|| self.i18n.get(Locale::En.code()))
            .cloned()
            .unwrap_or_else(|| LocalizedText {
                name: self.id.clone(),
                description: String::new(),
            })
    }
}

/// Aggregated result of running a safety-first scan across declarative rules.
#[derive(Debug, Clone, Default)]
pub struct SafeScanSummary {
    pub items: Vec<ScannedItem>,
    pub skipped_locked: usize,
    pub skipped_cloud: usize,
    pub skipped_recent: usize,
    pub skipped_whitelisted: usize,
}

impl SafeScanSummary {
    pub fn total_reclaimable_bytes(&self) -> u64 {
        self.items.iter().map(|i| i.size_bytes).sum()
    }
}

/// Loads and validates all `.toml` rule catalogs from a directory, enforcing
/// the `validate_rule_pattern_safety` sandbox on every path expression.
pub fn load_rules_from_dir(rules_dir: &Path) -> Result<Vec<CleaningRule>> {
    if !rules_dir.exists() {
        return load_embedded_default_rules();
    }

    let mut rules = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(rules_dir)
        .with_context(|| format!("Failed to read rules directory {}", rules_dir.display()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|e| e.path());

    for entry in entries {
        let path = entry.path();
        if path.extension().and_then(|s| s.to_str()) != Some("toml") {
            continue;
        }

        let raw = fs::read_to_string(&path)
            .with_context(|| format!("Failed to read rule file {}", path.display()))?;
        let catalog: RuleCatalogFile = toml::from_str(&raw)
            .with_context(|| format!("Invalid TOML syntax in {}", path.display()))?;

        for rule in catalog.rule {
            for pattern in &rule.paths {
                let verdict = validate_rule_pattern_safety(pattern);
                if !verdict.is_allowed() {
                    bail!(
                        "Rule '{}' in {} failed pattern safety validation: {:?}",
                        rule.id,
                        path.display(),
                        verdict
                    );
                }
            }
            rules.push(rule);
        }
    }

    if rules.is_empty() {
        return load_embedded_default_rules();
    }

    Ok(rules)
}

/// Loads the built-in TOML rule catalogs compiled directly into the binary so `AuraClean.exe`
/// works as a standalone 1-click portable executable from any directory.
pub fn load_embedded_default_rules() -> Result<Vec<CleaningRule>> {
    const EMBEDDED_FILES: &[(&str, &str)] = &[
        (
            "browsers.toml",
            include_str!("../../../rules/browsers.toml"),
        ),
        (
            "devtools.toml",
            include_str!("../../../rules/devtools.toml"),
        ),
        ("gaming.toml", include_str!("../../../rules/gaming.toml")),
        (
            "system_windows.toml",
            include_str!("../../../rules/system_windows.toml"),
        ),
    ];

    let mut rules = Vec::new();
    for (name, raw) in EMBEDDED_FILES {
        let catalog: RuleCatalogFile =
            toml::from_str(raw).with_context(|| format!("Invalid embedded TOML in {name}"))?;
        for rule in catalog.rule {
            for pattern in &rule.paths {
                let verdict = validate_rule_pattern_safety(pattern);
                if !verdict.is_allowed() {
                    bail!(
                        "Embedded rule '{}' in {} failed pattern safety validation: {:?}",
                        rule.id,
                        name,
                        verdict
                    );
                }
            }
            rules.push(rule);
        }
    }
    Ok(rules)
}

/// Expands basic Windows environment variables (`%LOCALAPPDATA%`, `%APPDATA%`, `%TEMP%`, `%USERPROFILE%`)
/// for safe local evaluation.
pub fn expand_windows_env_vars(pattern: &str) -> String {
    let mut result = pattern.to_string();
    for var in ["LOCALAPPDATA", "APPDATA", "TEMP", "TMP", "USERPROFILE"] {
        let token = format!("%{var}%");
        if result.to_ascii_uppercase().contains(&token)
            && let Ok(val) = std::env::var(var)
        {
            result = replace_case_insensitive(&result, &token, &val);
        }
    }
    result
}

fn replace_case_insensitive(haystack: &str, needle_upper: &str, replacement: &str) -> String {
    let upper = haystack.to_ascii_uppercase();
    if let Some(idx) = upper.find(needle_upper) {
        let mut out = String::with_capacity(haystack.len() + replacement.len());
        out.push_str(&haystack[..idx]);
        out.push_str(replacement);
        out.push_str(&haystack[idx + needle_upper.len()..]);
        out
    } else {
        haystack.to_string()
    }
}

/// Scans a target directory under a specific `CleaningRule`, enforcing all 4 safety guards:
/// 1. Immutable Whitelist (`evaluate_path_whitelist`)
/// 2. Cloud Placeholder & Reparse Point Guard (`inspect_path_attributes`)
/// 3. File Age Guard (`is_older_than_threshold`)
/// 4. Kernel Exclusive Lock Guard (`is_file_exclusively_openable`)
pub fn scan_directory_with_rule(
    base_dir: &Path,
    rule: &CleaningRule,
    locale: Locale,
    max_files: usize,
) -> SafeScanSummary {
    let mut summary = SafeScanSummary::default();
    if !base_dir.exists() {
        return summary;
    }

    let min_age = Duration::from_secs(rule.min_age_hours.saturating_mul(3600));
    let localized = rule.localized(locale);

    for entry_res in jwalk::WalkDir::new(base_dir)
        .follow_links(false)
        .max_depth(4)
        .skip_hidden(false)
    {
        if summary.items.len() >= max_files {
            break;
        }

        let Ok(entry) = entry_res else {
            continue;
        };
        let path = entry.path();
        if path == base_dir {
            continue;
        }

        // 1. Cloud & Reparse Point Guard
        match inspect_path_attributes(&path) {
            Ok(AttributeSafetyVerdict::LocalNormalFile) => {}
            Ok(AttributeSafetyVerdict::SkippedCloudPlaceholder) => {
                summary.skipped_cloud += 1;
                continue;
            }
            Ok(AttributeSafetyVerdict::SkippedReparsePoint) | Err(_) => {
                continue;
            }
        }

        if !entry.file_type().is_file() {
            continue;
        }

        // 2. Immutable Whitelist Guard
        if !evaluate_path_whitelist(&path).is_allowed() {
            summary.skipped_whitelisted += 1;
            continue;
        }

        // 3. Age Threshold Guard (24h default)
        match is_older_than_threshold(&path, min_age) {
            Ok(true) => {}
            Ok(false) => {
                summary.skipped_recent += 1;
                continue;
            }
            Err(_) => continue,
        }

        // 4. Active Lock & Sharing Guard
        if !is_file_exclusively_openable(&path) {
            summary.skipped_locked += 1;
            continue;
        }

        let size_bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
        summary.items.push(ScannedItem {
            item_id: Uuid::new_v4(),
            rule_id: rule.id.clone(),
            path,
            size_bytes,
            safety_level: rule.safety_level,
            quarantine_tier: rule.quarantine_tier,
            localized_title: localized.name.clone(),
            localized_reason: localized.description.clone(),
        });
    }

    summary
}

/// Resolves concrete base directories from a rule's path patterns for safe bounded scanning.
pub fn resolve_base_directories(rule: &CleaningRule) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    for pattern in &rule.paths {
        let expanded = expand_windows_env_vars(pattern);
        // Strip trailing wildcard segment (`\*` or `\*.dmp`) when wildcard is only at the leaf
        let prefix = expanded
            .split('*')
            .next()
            .unwrap_or(&expanded)
            .trim_end_matches('\\');
        if !prefix.is_empty() {
            let candidate = PathBuf::from(prefix);
            if candidate.exists() && candidate.is_dir() && !dirs.contains(&candidate) {
                dirs.push(candidate);
            }
        }
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn test_all_repository_toml_rules_parse_and_pass_safety_sandbox() {
        let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let rules_dir = manifest_dir.parent().unwrap().parent().unwrap().join("rules");
        let rules = load_rules_from_dir(&rules_dir).expect("All rules/*.toml must be valid");
        assert!(rules.len() >= 8, "Expected at least 8 initial rules");

        for rule in &rules {
            let en = rule.localized(Locale::En);
            let ru = rule.localized(Locale::Ru);
            assert!(!en.name.is_empty(), "Missing English name for {}", rule.id);
            assert!(!ru.name.is_empty(), "Missing Russian name for {}", rule.id);
            assert!(
                !en.description.is_empty(),
                "Missing English description for {}",
                rule.id
            );
            assert!(
                !ru.description.is_empty(),
                "Missing Russian description for {}",
                rule.id
            );
        }
    }

    #[test]
    fn test_registry_command_line_heuristic_parser() {
        let p1 = extract_executable_path_from_registry_string(
            r#""C:\Program Files\Cyberpunk 2077\bin\x64\Cyberpunk2077.exe" --launcher-skip -silent"#,
        )
        .unwrap();
        assert_eq!(
            p1,
            PathBuf::from(r"C:\Program Files\Cyberpunk 2077\bin\x64\Cyberpunk2077.exe")
        );

        let p2 = extract_executable_path_from_registry_string(
            r"C:\Games\OldApp\app.exe.FriendlyAppName",
        )
        .unwrap();
        assert_eq!(p2, PathBuf::from(r"C:\Games\OldApp\app.exe"));

        let p3 = extract_executable_path_from_registry_string(r"C:\Tools\tool.exe,0").unwrap();
        assert_eq!(p3, PathBuf::from(r"C:\Tools\tool.exe"));

        // Indirect hosts like rundll32 must be ignored for safety
        assert!(
            extract_executable_path_from_registry_string(r"rundll32.exe shell32.dll,Control_RunDLL")
                .is_none()
        );
    }
}

