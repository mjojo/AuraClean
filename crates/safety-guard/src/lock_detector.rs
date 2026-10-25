//! Win32 Restart Manager API batch inspector and kernel exclusive-access lock detector.
//!
//! Ensures AuraClean never attempts to delete or truncate a file currently held open
//! by Windows or any background application.

use crate::whitelist::to_extended_length_path;
use std::collections::HashMap;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{CloseHandle, ERROR_MORE_DATA, ERROR_SUCCESS, GENERIC_READ, GENERIC_WRITE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_NONE, OPEN_EXISTING,
};
use windows::Win32::System::RestartManager::{
    CCH_RM_SESSION_KEY, RM_PROCESS_INFO, RmEndSession, RmGetList, RmRegisterResources,
    RmStartSession,
};
use windows::core::{PCWSTR, PWSTR};

/// Maximum number of file paths registered per `RmRegisterResources` batch call.
const RM_BATCH_SIZE: usize = 250;

/// Result of checking whether a file is currently in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileLockStatus {
    /// File is not locked by any process and can be safely quarantined.
    Unlocked,
    /// File is locked according to a kernel exclusive share check (`dwShareMode = 0`).
    LockedExclusiveShare,
    /// File is held open by one or more named processes identified via Windows Restart Manager.
    LockedByProcesses(Vec<String>),
}

impl FileLockStatus {
    pub fn is_locked(&self) -> bool {
        !matches!(self, Self::Unlocked)
    }
}

/// Fast kernel-level probe using `CreateFileW` with `FILE_SHARE_NONE` (`dwShareMode = 0`).
/// If any process has an open handle to the file (for reading, writing, or mapping),
/// Windows immediately returns `ERROR_SHARING_VIOLATION` without modifying the file.
pub fn is_file_exclusively_openable(path: &Path) -> bool {
    let extended = to_extended_length_path(path);
    let wide: Vec<u16> = extended
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: `wide` is a valid null-terminated UTF-16 string and `OPEN_EXISTING` with `FILE_SHARE_NONE`
    // only probes handle availability and closes the handle immediately.
    unsafe {
        let handle_res = CreateFileW(
            PCWSTR(wide.as_ptr()),
            (GENERIC_READ | GENERIC_WRITE).0,
            FILE_SHARE_NONE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        );

        match handle_res {
            Ok(handle) => {
                let _ = CloseHandle(handle);
                true
            }
            Err(_) => false,
        }
    }
}

/// Inspects a batch of candidate files using both kernel exclusive-handle probes and
/// the Windows Restart Manager API (`RmStartSession`, `RmRegisterResources`, `RmGetList`).
pub fn inspect_files_lock_status(paths: &[PathBuf]) -> HashMap<PathBuf, FileLockStatus> {
    let mut results = HashMap::with_capacity(paths.len());
    let mut candidates_for_rm = Vec::new();

    for path in paths {
        if !path.exists() {
            results.insert(path.clone(), FileLockStatus::Unlocked);
            continue;
        }

        if is_file_exclusively_openable(path) {
            results.insert(path.clone(), FileLockStatus::Unlocked);
        } else {
            // File failed exclusive open; queue it for Restart Manager to identify locking processes
            results.insert(path.clone(), FileLockStatus::LockedExclusiveShare);
            candidates_for_rm.push(path.clone());
        }
    }

    for chunk in candidates_for_rm.chunks(RM_BATCH_SIZE) {
        for p in chunk {
            if let Some(procs) = query_restart_manager_for_file(p)
                && !procs.is_empty()
            {
                results.insert(p.clone(), FileLockStatus::LockedByProcesses(procs));
            }
        }
    }

    results
}

/// Queries the Windows Restart Manager API for a single locked file to obtain the human-readable
/// names of the processes holding it open (e.g., `chrome.exe (PID 1420)`).
pub fn query_restart_manager_for_file(path: &Path) -> Option<Vec<String>> {
    let wide_path: Vec<u16> = path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // SAFETY: Standard Win32 Restart Manager session lifecycle (`RmStartSession` -> `RmRegisterResources` -> `RmGetList` -> `RmEndSession`).
    unsafe {
        let mut session_handle: u32 = 0;
        let mut session_key = [0u16; (CCH_RM_SESSION_KEY as usize) + 1];

        let start_err = RmStartSession(&mut session_handle, 0, PWSTR(session_key.as_mut_ptr()));
        if start_err != ERROR_SUCCESS {
            return None;
        }

        struct SessionGuard(u32);
        impl Drop for SessionGuard {
            fn drop(&mut self) {
                unsafe {
                    let _ = RmEndSession(self.0);
                }
            }
        }
        let _guard = SessionGuard(session_handle);

        let resources = [PCWSTR(wide_path.as_ptr())];
        let reg_err = RmRegisterResources(session_handle, Some(&resources), None, None);
        if reg_err != ERROR_SUCCESS {
            return None;
        }

        let mut proc_info_needed: u32 = 0;
        let mut proc_info_count: u32 = 0;
        let mut reboot_reasons: u32 = 0;

        let list_err = RmGetList(
            session_handle,
            &mut proc_info_needed,
            &mut proc_info_count,
            None,
            &mut reboot_reasons,
        );

        if list_err == ERROR_SUCCESS && proc_info_needed == 0 {
            return Some(Vec::new());
        }

        if list_err != ERROR_MORE_DATA || proc_info_needed == 0 {
            return None;
        }

        let mut proc_infos = vec![RM_PROCESS_INFO::default(); proc_info_needed as usize];
        proc_info_count = proc_info_needed;

        let list_err2 = RmGetList(
            session_handle,
            &mut proc_info_needed,
            &mut proc_info_count,
            Some(proc_infos.as_mut_ptr()),
            &mut reboot_reasons,
        );

        if list_err2 != ERROR_SUCCESS {
            return None;
        }

        let mut holders = Vec::with_capacity(proc_info_count as usize);
        for info in proc_infos.iter().take(proc_info_count as usize) {
            let name_len = info
                .strAppName
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(info.strAppName.len());
            let app_name = String::from_utf16_lossy(&info.strAppName[..name_len]);
            let pid = info.Process.dwProcessId;
            holders.push(format!("{app_name} (PID {pid})"));
        }

        Some(holders)
    }
}
