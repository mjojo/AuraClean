//! Windows Known Folder Resolver (`SHGetKnownFolderPath`), Hidden Folder (`AppData`, `.cache`),
//! and Cyrillic / Unicode Path Expander.
//!
//! Solves 3 classic Windows cleaner bugs:
//! 1. Cyrillic usernames (`C:\Users\Вит\...`) or Cyrillic folder names (`Мои документы`)
//!    breaking naive ASCII case-folding or byte-length `MAX_PATH` checks.
//! 2. Hidden system/user folders (`AppData` has `FILE_ATTRIBUTE_HIDDEN`, plus dot-folders like `.gradle`, `.venv`)
//!    being skipped or failing intermediate wildcard expansion (`...\User Data\*\Cache\...`).
//! 3. Relocated or localized `Documents` / `Downloads` folders (e.g., moved to `D:\Мои Документы`
//!    or redirected by OneDrive) resolved via native Win32 `SHGetKnownFolderPath`.

use std::ffi::OsString;
use std::fs;
use std::os::windows::ffi::OsStringExt;
use std::path::{Path, PathBuf};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::UI::Shell::{
    FOLDERID_Documents, FOLDERID_Downloads, FOLDERID_LocalAppData, FOLDERID_LocalAppDataLow,
    FOLDERID_Profile, FOLDERID_ProgramData, FOLDERID_RoamingAppData, KF_FLAG_DEFAULT,
    SHGetKnownFolderPath,
};
use windows::core::GUID;

/// Queries Win32 `SHGetKnownFolderPath` to get the exact UTF-16 path of a Windows Known Folder,
/// accurately handling Cyrillic usernames, localized Russian Windows folders, and user-relocated
/// `Documents` / `Downloads` directories on secondary drives (`D:\`, `E:\`).
pub fn query_known_folder(folder_id: &GUID) -> Option<PathBuf> {
    // SAFETY: `SHGetKnownFolderPath` allocates a null-terminated UTF-16 string via COM task allocator,
    // which we immediately copy into an `OsString` and free with `CoTaskMemFree`.
    unsafe {
        let Ok(pwstr) = SHGetKnownFolderPath(folder_id, KF_FLAG_DEFAULT, None) else {
            return None;
        };
        if pwstr.is_null() {
            return None;
        }

        let mut len = 0usize;
        while *pwstr.0.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(pwstr.0, len);
        let os_str = OsString::from_wide(slice);
        CoTaskMemFree(Some(pwstr.0 as *const _));
        Some(PathBuf::from(os_str))
    }
}

/// Returns the user's true `Documents` ("Мои документы") directory via `SHGetKnownFolderPath`,
/// plus any secondary `Documents` / `Мои документы` directory under `%USERPROFILE%`.
pub fn resolve_user_documents_dirs() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Some(known_docs) = query_known_folder(&FOLDERID_Documents)
        && known_docs.exists()
    {
        dirs.push(known_docs);
    }

    if let Some(profile) = query_known_folder(&FOLDERID_Profile)
        .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from))
    {
        for candidate_name in ["Documents", "Мои документы", "OneDrive\\Documents", "OneDrive\\Документы"] {
            let candidate = profile.join(candidate_name);
            if candidate.exists() && candidate.is_dir() && !dirs.contains(&candidate) {
                dirs.push(candidate);
            }
        }
    }

    dirs
}

/// Returns all hidden `AppData` roots (`Local`, `LocalLow`, `Roaming`) for the current user,
/// even though `C:\Users\<Имя>\AppData` is marked `FILE_ATTRIBUTE_HIDDEN` by Windows.
pub fn resolve_user_appdata_roots() -> Vec<(&'static str, PathBuf)> {
    let mut roots = Vec::new();

    if let Some(local) = query_known_folder(&FOLDERID_LocalAppData)
        .or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from))
        && local.exists()
    {
        roots.push(("AppData\\Local", local));
    }

    if let Some(locallow) = query_known_folder(&FOLDERID_LocalAppDataLow)
        && locallow.exists()
    {
        roots.push(("AppData\\LocalLow", locallow));
    }

    if let Some(roaming) = query_known_folder(&FOLDERID_RoamingAppData)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        && roaming.exists()
    {
        roots.push(("AppData\\Roaming", roaming));
    }

    if let Some(progdata) = query_known_folder(&FOLDERID_ProgramData)
        .or_else(|| std::env::var_os("ProgramData").map(PathBuf::from))
        && progdata.exists()
    {
        roots.push(("ProgramData (Hidden)", progdata));
    }

    roots
}

/// Expands environment tokens AND Known Folder tokens (`%DOCUMENTS%`, `%DOWNLOADS%`,
/// `%LOCALAPPDATA%`, `%APPDATA%`, `%LOCALLOW%`, `%PROGRAMDATA%`, `%USERPROFILE%`, `%TEMP%`)
/// with full Unicode / Cyrillic fidelity.
pub fn expand_known_and_env_vars(pattern: &str) -> String {
    let mut result = pattern.replace('/', r"\");

    let replacements: [(&str, Option<PathBuf>); 8] = [
        ("%DOCUMENTS%", query_known_folder(&FOLDERID_Documents)),
        ("%DOWNLOADS%", query_known_folder(&FOLDERID_Downloads)),
        (
            "%LOCALAPPDATA%",
            query_known_folder(&FOLDERID_LocalAppData)
                .or_else(|| std::env::var_os("LOCALAPPDATA").map(PathBuf::from)),
        ),
        (
            "%LOCALLOW%",
            query_known_folder(&FOLDERID_LocalAppDataLow),
        ),
        (
            "%APPDATA%",
            query_known_folder(&FOLDERID_RoamingAppData)
                .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from)),
        ),
        (
            "%PROGRAMDATA%",
            query_known_folder(&FOLDERID_ProgramData)
                .or_else(|| std::env::var_os("ProgramData").map(PathBuf::from)),
        ),
        (
            "%USERPROFILE%",
            query_known_folder(&FOLDERID_Profile)
                .or_else(|| std::env::var_os("USERPROFILE").map(PathBuf::from)),
        ),
        ("%TEMP%", std::env::var_os("TEMP").map(PathBuf::from)),
    ];

    for (token, maybe_path) in replacements {
        if let Some(path) = maybe_path {
            result = replace_token_unicode_ci(&result, token, &path.to_string_lossy());
        }
    }

    result
}

fn replace_token_unicode_ci(haystack: &str, token_upper: &str, replacement: &str) -> String {
    let upper = haystack.to_uppercase();
    if let Some(idx) = upper.find(token_upper) {
        let mut out = String::with_capacity(haystack.len() + replacement.len());
        out.push_str(&haystack[..idx]);
        out.push_str(replacement);
        out.push_str(&haystack[idx + token_upper.len()..]);
        out
    } else {
        haystack.to_string()
    }
}

/// Expands a rule path pattern that may contain intermediate wildcards (`*`) inside hidden
/// or Cyrillic directories (for example:
/// `C:\Users\Вит\AppData\Local\Google\Chrome\User Data\*\Cache\Cache_Data\*`).
///
/// Previously, splitting on the first `*` stopped at `...\User Data` (which did not match `Default`
/// or `Profile 1`). This function walks wildcard directory segments step-by-step, including
/// hidden directories (`AppData`, `.cache`, etc.), and returns all concrete existing directories.
pub fn expand_wildcard_directories(pattern: &str) -> Vec<PathBuf> {
    let expanded = expand_known_and_env_vars(pattern);

    // Strip trailing file mask such as `\*` or `\*.dmp` or `\*.log`
    let dir_pattern = if let Some((parent, leaf)) = expanded.rsplit_once('\\') {
        if leaf.contains('*') {
            parent
        } else {
            expanded.as_str()
        }
    } else {
        expanded.as_str()
    };

    if !dir_pattern.contains('*') {
        let p = PathBuf::from(dir_pattern);
        return if p.exists() && p.is_dir() {
            vec![p]
        } else {
            Vec::new()
        };
    }

    // Split around intermediate `*` segments (e.g. `<root>\*\<tail>`)
    let segments: Vec<&str> = dir_pattern.split('\\').collect();
    let mut current_paths = Vec::new();

    for (idx, seg) in segments.iter().enumerate() {
        if idx == 0 {
            current_paths.push(PathBuf::from(format!("{seg}\\")));
            continue;
        }

        if *seg == "*" {
            let mut next_paths = Vec::new();
            for base in &current_paths {
                if let Ok(entries) = fs::read_dir(base) {
                    for entry in entries.flatten() {
                        let p = entry.path();
                        if p.is_dir() {
                            next_paths.push(p);
                        }
                    }
                }
            }
            current_paths = next_paths;
        } else {
            current_paths = current_paths
                .into_iter()
                .map(|base| base.join(seg))
                .filter(|p| p.exists() && p.is_dir())
                .collect();
        }

        if current_paths.is_empty() {
            break;
        }
    }

    current_paths
}

/// Checks if a file or directory has the Win32 `FILE_ATTRIBUTE_HIDDEN` (`0x2`) attribute
/// or starts with a dot (`.`).
pub fn is_hidden_entry(path: &Path) -> bool {
    use std::os::windows::fs::MetadataExt;
    const FILE_ATTRIBUTE_HIDDEN_FLAG: u32 = 0x0000_0002;

    if let Some(name) = path.file_name().and_then(|n| n.to_str())
        && name.starts_with('.')
    {
        return true;
    }

    if let Ok(meta) = fs::symlink_metadata(path) {
        (meta.file_attributes() & FILE_ATTRIBUTE_HIDDEN_FLAG) != 0
    } else {
        false
    }
}
