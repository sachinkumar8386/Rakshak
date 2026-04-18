use std::path::{Path, PathBuf};
use windows::Win32::Foundation::{HANDLE, CloseHandle, DUPLICATE_SAME_ACCESS};
use windows::Win32::System::Threading::{OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_DUP_HANDLE, GetCurrentProcess};
use windows::Win32::Storage::FileSystem::{
    GetFileType, FILE_TYPE_DISK, GetFinalPathNameByHandleW, FILE_NAME_NORMALIZED, QueryDosDeviceW,
};
use std::collections::HashMap;
use std::sync::RwLock;

lazy_static::lazy_static! {
    static ref DEVICE_MAP: RwLock<HashMap<String, String>> = RwLock::new(HashMap::new());
}

/// Initializes the device map by querying all drive letters.
pub fn update_device_map() {
    let mut map = DEVICE_MAP.write().unwrap();
    for drive_letter in (b'A'..=b'Z').map(|b| b as char) {
        let drive = format!("{}:", drive_letter);
        let drive_hstring = windows::core::HSTRING::from(&drive);
        let mut buffer = [0u16; 1024];
        let len = unsafe { QueryDosDeviceW(windows::core::PCWSTR(drive_hstring.as_ptr()), Some(&mut buffer)) };
        if len > 0 {
            let device_path = String::from_utf16_lossy(&buffer[..len as usize]).trim_matches('\0').to_string();
            // device_path will look like "\Device\HarddiskVolume3"
            map.insert(device_path, drive);
        }
    }
}

/// Translates an NT device path (e.g., \Device\HarddiskVolume3\Users\...) to a DOS path (C:\Users\...).
pub fn resolve_kernel_path(nt_path: &str) -> String {
    let map = DEVICE_MAP.read().unwrap();
    for (device, drive) in map.iter() {
        if nt_path.starts_with(device) {
            return nt_path.replace(device, drive);
        }
    }
    nt_path.to_string()
}

// ─── Windows Internal APIs ──────────────────────────────────────────────────
// We link directly to ntdll to avoid dependency conflicts between ntapi and winapi.

#[link(name = "ntdll")]
extern "system" {
    fn NtQuerySystemInformation(
        system_information_class: u32,
        system_information: *mut std::ffi::c_void,
        system_information_length: u32,
        return_length: *mut u32,
    ) -> windows::core::HRESULT;
}

#[repr(C)]
struct SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    unique_process_id: u16,
    creator_back_trace_index: u16,
    object_type_index: u8,
    handle_attributes: u8,
    handle_value: u16,
    object: *mut std::ffi::c_void,
    granted_access: u32,
}

#[repr(C)]
struct SYSTEM_HANDLE_INFORMATION {
    number_of_handles: u32,
    handles: [SYSTEM_HANDLE_TABLE_ENTRY_INFO; 1],
}

const SYSTEM_HANDLE_INFORMATION_CLASS: u32 = 16;

/// Use NtQuerySystemInformation to find which process owns a handle to the given file path.
/// This is a high-cost but high-precision operation.
pub fn find_pid_by_open_handle(target_path: &Path) -> Option<u32> {
    let mut buffer = vec![0u8; 1024 * 1024]; // Start with 1MB
    let mut return_length = 0u32;

    unsafe {
        loop {
            let status = NtQuerySystemInformation(
                SYSTEM_HANDLE_INFORMATION_CLASS,
                buffer.as_mut_ptr() as *mut _,
                buffer.len() as u32,
                &mut return_length,
            );

            if status.is_ok() {
                break;
            } else if status.0 as u32 == 0xC0000004 { // STATUS_INFO_LENGTH_MISMATCH
                buffer.resize(return_length as usize, 0);
            } else {
                return None;
            }
        }

        let handle_info = &*(buffer.as_ptr() as *const SYSTEM_HANDLE_INFORMATION);
        let handles = std::slice::from_raw_parts(
            handle_info.handles.as_ptr(),
            handle_info.number_of_handles as usize,
        );

        for handle_entry in handles {
            if let Some(pid) = check_handle_match(handle_entry, target_path) {
                return Some(pid);
            }
        }
    }

    None
}

unsafe fn check_handle_match(entry: &SYSTEM_HANDLE_TABLE_ENTRY_INFO, target_path: &Path) -> Option<u32> {
    let pid = entry.unique_process_id as u32;
    if pid <= 4 { return None; }

    let process_handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, false, pid) {
        Ok(h) => h,
        Err(_) => return None,
    };

    let mut dup_handle = HANDLE::default();
    let current_process = GetCurrentProcess();
    
    let success = windows::Win32::Foundation::DuplicateHandle(
        process_handle,
        HANDLE(entry.handle_value as *mut _),
        current_process,
        &mut dup_handle,
        0,
        false,
        DUPLICATE_SAME_ACCESS,
    );

    if success.is_ok() {
        if GetFileType(dup_handle) == FILE_TYPE_DISK {
            let mut path_buf = [0u16; 1024];
            let len = GetFinalPathNameByHandleW(
                dup_handle,
                &mut path_buf,
                FILE_NAME_NORMALIZED,
            );

            if len > 0 && len < 1024 {
                let path_str = String::from_utf16_lossy(&path_buf[..len as usize]);
                let normalized_path = path_str.trim_start_matches("\\\\?\\");
                
                // Use dunce for robust comparison (strips \\?\ where safe)
                let canon_target = dunce::canonicalize(target_path).unwrap_or_else(|_| target_path.to_path_buf());
                let canon_normalized = dunce::canonicalize(normalized_path).unwrap_or_else(|_| std::path::PathBuf::from(normalized_path));

                log::debug!("windows_util: Checking path match: {} vs {}", canon_normalized.display(), canon_target.display());

                if canon_normalized.to_string_lossy().eq_ignore_ascii_case(&canon_target.to_string_lossy()) {
                    log::info!("windows_util: Found PID {} for path {}", pid, normalized_path);
                    let _ = CloseHandle(dup_handle);
                    let _ = CloseHandle(process_handle);
                    return Some(pid);
                }
            }
        }
        let _ = CloseHandle(dup_handle);
    } else {
        // Log errors only if they aren't common permission issues
        let err = windows::core::Error::from_win32();
        if err.code().0 as u32 != 5 { // Access Denied is common for many handles
            log::trace!("windows_util: DuplicateHandle failed for PID {}: {}", pid, err);
        }
    }

    let _ = CloseHandle(process_handle);
    None
}
