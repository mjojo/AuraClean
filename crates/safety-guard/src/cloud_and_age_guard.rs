//! Cloud file recall guard, Reparse Point (symlink/junction) guard, and 24-Hour File Age Guard.
//!
//! Ensures AuraClean never triggers accidental OneDrive/iCloud hydration downloads,
//! never follows junction loops, and never deletes active session temporary files.

use std::fs;
use std::os::windows::fs::MetadataExt;
use std::path::Path;
use std::time::{Duration, SystemTime};

/// Win32 File Attribute flags for cloud placeholders and reparse points.
pub const FILE_ATTRIBUTE_REPARSE_POINT_FLAG: u32 = 0x0000_0400;
pub const FILE_ATTRIBUTE_OFFLINE_FLAG: u32 = 0x0000_1000;
pub const FILE_ATTRIBUTE_RECALL_ON_OPEN_FLAG: u32 = 0x0004_0000;
pub const FILE_ATTRIBUTE_PINNED_FLAG: u32 = 0x0008_0000;
pub const FILE_ATTRIBUTE_UNPINNED_FLAG: u32 = 0x0010_0000;
pub const FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS_FLAG: u32 = 0x0040_0000;

/// Verdict for cloud-placeholder and symlink/reparse inspection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeSafetyVerdict {
    /// Normal local file safe to inspect.
    LocalNormalFile,
    /// File is a cloud placeholder (OneDrive/iCloud/Dropbox Files On-Demand); must not be opened or deleted.
    SkippedCloudPlaceholder,
    /// File or directory is a symlink/junction reparse point; must not be traversed or deleted.
    SkippedReparsePoint,
}

/// Evaluates raw Win32 `dwFileAttributes` bitmask without opening the file handle
/// (which itself could trigger a cloud recall).
pub const fn evaluate_win32_attributes(attributes: u32) -> AttributeSafetyVerdict {
    // Check cloud recall flags first (OneDrive Files On-Demand, iCloud, Cloud Filter API)
    if (attributes & FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS_FLAG) != 0
        || (attributes & FILE_ATTRIBUTE_RECALL_ON_OPEN_FLAG) != 0
        || (attributes & FILE_ATTRIBUTE_OFFLINE_FLAG) != 0
        || ((attributes & FILE_ATTRIBUTE_UNPINNED_FLAG) != 0
            && (attributes & FILE_ATTRIBUTE_PINNED_FLAG) == 0)
    {
        return AttributeSafetyVerdict::SkippedCloudPlaceholder;
    }

    if (attributes & FILE_ATTRIBUTE_REPARSE_POINT_FLAG) != 0 {
        return AttributeSafetyVerdict::SkippedReparsePoint;
    }

    AttributeSafetyVerdict::LocalNormalFile
}

/// Queries `symlink_metadata` (which uses `GetFileAttributesExW` / `FindFirstFileW` without following links
/// or recalling cloud data) and returns the attribute safety verdict.
pub fn inspect_path_attributes(path: &Path) -> std::io::Result<AttributeSafetyVerdict> {
    let meta = fs::symlink_metadata(path)?;
    Ok(evaluate_win32_attributes(meta.file_attributes()))
}

/// Checks whether a file satisfies the minimum age threshold (default 24 hours for temp directories).
/// Returns `true` if the file is older than `min_age` and safe to clean, or `false` if it was created
/// or modified recently and must be shielded.
pub fn is_older_than_threshold(path: &Path, min_age: Duration) -> std::io::Result<bool> {
    if min_age.is_zero() {
        return Ok(true);
    }

    let meta = fs::symlink_metadata(path)?;
    let now = SystemTime::now();

    if let Ok(modified) = meta.modified()
        && let Ok(elapsed) = now.duration_since(modified)
        && elapsed < min_age
    {
        return Ok(false);
    }

    if let Ok(created) = meta.created()
        && let Ok(elapsed) = now.duration_since(created)
        && elapsed < min_age
    {
        return Ok(false);
    }

    Ok(true)
}
