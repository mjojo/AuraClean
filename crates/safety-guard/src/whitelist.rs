//! Compile-time immutable whitelist and path sanitizer for Windows OS integrity.

use std::path::{Path, PathBuf};

/// Hardcoded critical Windows system prefixes that AuraClean must NEVER modify or delete,
/// regardless of user input or external TOML rule definitions.
pub const IMMUTABLE_SYSTEM_PREFIXES: &[&str] = &[
    r"c:\windows\winsxs",
    r"c:\windows\system32\config",
    r"c:\windows\system32\driverstore",
    r"c:\windows\system32\drivers",
    r"c:\windows\system32\catroot",
    r"c:\windows\system32\catroot2",
    r"c:\windows\syswow64\config",
    r"c:\windows\boot",
    r"c:\windows\servicing",
    r"c:\efi",
    r"c:\recovery",
    r"c:\system volume information",
];

/// File extensions that are unconditionally blocked from deletion across the entire system.
pub const IMMUTABLE_EXTENSIONS: &[&str] = &[
    "sys", "drv", "efi", "cat", "hiv", "ntfs",
];

/// Binary extensions that are blocked unless located inside an explicitly designated cache/temp folder.
pub const PROTECTED_BINARY_EXTENSIONS: &[&str] = &[
    "dll", "exe", "ocx", "cpl", "msi", "msp",
];

/// Detailed verdict returned by the Immutable Whitelist evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WhitelistVerdict {
    /// Path is outside immutable system zones and allowed for further inspection.
    Allowed,
    /// Blocked because path is inside a critical Windows OS directory.
    BlockedSystemDirectory(&'static str),
    /// Blocked because file extension is an immutable kernel/driver/boot type.
    BlockedSystemExtension(String),
    /// Blocked because executable/library is outside an isolated cache or temp directory.
    BlockedProtectedBinary(String),
    /// Blocked because rule pattern attempts a root or profile-wide wildcard traversal.
    BlockedUnsafeRulePattern(String),
}

impl WhitelistVerdict {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed)
    }
}

/// Normalizes a Windows path for case-insensitive comparison, stripping any `\\?\` extended prefix.
pub fn normalize_for_comparison(path: &Path) -> String {
    let raw = path.to_string_lossy();
    let stripped = raw
        .strip_prefix(r"\\?\UNC\")
        .map(|s| format!(r"\\{s}"))
        .or_else(|| raw.strip_prefix(r"\\?\").map(str::to_owned))
        .unwrap_or_else(|| raw.into_owned());

    stripped.replace('/', r"\").to_ascii_lowercase()
}

/// Converts a standard Windows path into an Extended-Length Path (`\\?\C:\...`) when needed
/// to safely handle paths exceeding `MAX_PATH` (260 characters), such as deep `node_modules`.
pub fn to_extended_length_path(path: &Path) -> PathBuf {
    let raw = path.to_string_lossy();
    if raw.starts_with(r"\\?\") {
        return path.to_path_buf();
    }
    if path.is_absolute() && raw.len() >= 240 {
        if let Some(stripped_unc) = raw.strip_prefix(r"\\") {
            return PathBuf::from(format!(r"\\?\UNC\{stripped_unc}"));
        }
        return PathBuf::from(format!(r"\\?\{raw}"));
    }
    path.to_path_buf()
}

/// Evaluates whether a candidate file path is shielded by the compile-time immutable whitelist.
pub fn evaluate_path_whitelist(path: &Path) -> WhitelistVerdict {
    let normalized = normalize_for_comparison(path);

    // Block root drive or top-level system directories directly
    if normalized == r"c:\"
        || normalized == "c:"
        || normalized == r"c:\windows"
        || normalized == r"c:\windows\"
        || normalized == r"c:\windows\system32"
        || normalized == r"c:\windows\syswow64"
        || normalized == r"c:\program files"
        || normalized == r"c:\program files (x86)"
        || normalized == r"c:\users"
    {
        return WhitelistVerdict::BlockedSystemDirectory("Root OS Directory");
    }

    for &prefix in IMMUTABLE_SYSTEM_PREFIXES {
        if normalized == prefix || normalized.starts_with(&format!(r"{prefix}\")) {
            return WhitelistVerdict::BlockedSystemDirectory(prefix);
        }
    }

    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        let ext_lower = ext.to_ascii_lowercase();
        if IMMUTABLE_EXTENSIONS.contains(&ext_lower.as_str()) {
            return WhitelistVerdict::BlockedSystemExtension(ext_lower);
        }

        if PROTECTED_BINARY_EXTENSIONS.contains(&ext_lower.as_str())
            && !is_inside_isolated_cache_or_temp(&normalized)
        {
            return WhitelistVerdict::BlockedProtectedBinary(ext_lower);
        }
    }

    WhitelistVerdict::Allowed
}

/// Checks whether a normalized lowercase path sits inside a known isolated cache, temp, or build artifact folder.
fn is_inside_isolated_cache_or_temp(normalized_path: &str) -> bool {
    const SAFE_BINARY_CONTAINERS: &[&str] = &[
        r"\temp\",
        r"\appdata\local\temp\",
        r"\cache\",
        r"\code cache\",
        r"\gpucache\",
        r"\dxcache\",
        r"\glcache\",
        r"\d3dscache\",
        r"\node_modules\",
        r"\target\debug\",
        r"\target\release\",
    ];

    SAFE_BINARY_CONTAINERS
        .iter()
        .any(|marker| normalized_path.contains(marker))
}

/// Validates a declarative TOML rule path pattern before the scanner is allowed to execute it.
/// Prevents supply-chain or malformed rule patterns like `C:\*`, `%USERPROFILE%\*`, or `..` traversal.
pub fn validate_rule_pattern_safety(pattern: &str) -> WhitelistVerdict {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return WhitelistVerdict::BlockedUnsafeRulePattern("Empty rule pattern".to_string());
    }

    let lower = trimmed.replace('/', r"\").to_ascii_lowercase();
    if lower.split('\\').any(|segment| segment == "..") {
        return WhitelistVerdict::BlockedUnsafeRulePattern(format!(
            "Path traversal '..' is prohibited in rule pattern: {pattern}"
        ));
    }

    const FORBIDDEN_BROAD_PATTERNS: &[&str] = &[
        r"c:\*",
        r"d:\*",
        r"%systemdrive%\*",
        r"%windir%\*",
        r"%userprofile%\*",
        r"%userprofile%\documents\*",
        r"%userprofile%\desktop\*",
        r"%appdata%\*",
        r"%localappdata%\*",
    ];

    if FORBIDDEN_BROAD_PATTERNS.contains(&lower.as_str()) {
        return WhitelistVerdict::BlockedUnsafeRulePattern(format!(
            "Overly broad root wildcard pattern is prohibited: {pattern}"
        ));
    }

    WhitelistVerdict::Allowed
}
