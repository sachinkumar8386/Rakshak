/// Kill-Switch & Self-Defense
///
/// - `kill_process`: Tauri command to terminate a flagged PID.
/// - `get_flagged_pids`: Tauri command to retrieve the current suspect list.
/// - `elevate_priority`: Sets the Rakshak process to HIGH priority on Windows
///    so the OS cannot throttle it during an active attack.
use std::sync::Arc;
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, Signal, System};
use tauri::{AppHandle, Emitter};

use crate::defense;
use crate::watcher::{SecurityAlert, WatcherState};
use anyhow::{anyhow, Result as AnyResult};

#[cfg(windows)]
use windows::Win32::Foundation::CloseHandle;
#[cfg(windows)]
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};

// ─── Tauri Commands ──────────────────────────────────────────────────────────

/// Kill a specific process by PID. Returns a human-readable result string.
#[tauri::command]
pub fn kill_process(
    pid: u32,
    state: tauri::State<'_, Arc<WatcherState>>,
    app: AppHandle,
) -> Result<String, String> {
    log::warn!("[KillSwitch] Terminating PID {pid}");

    // --- PROTECTIONS ---
    if pid == 0 {
        log::info!("[KillSwitch] Ignoring termination request for PID 0 (System/Simulator)");
        return Ok("Ignored invalid or system PID 0".into());
    }
    if pid == std::process::id() {
        log::error!("[KillSwitch] ALERT: Attempted to terminate our own process!");
        return Err("Self-defense: Cannot terminate Rakshak core process".into());
    }

    let mut sys = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let sysinfo_pid = Pid::from_u32(pid);

    if let Some(proc) = sys.process(sysinfo_pid) {
        let name = proc.name().to_string_lossy().to_string();
        let _name_lower = name.to_lowercase();

        if defense::is_protected(pid, &name, &sys) {
            log::warn!(
                "[KillSwitch] Protected process, skipping: {} (PID {})",
                name,
                pid
            );
            if let Ok(mut flagged) = state.flagged_pids.lock() {
                flagged.retain(|&p| p != pid);
            }
            return Ok(format!(
                "Protected: {} (PID {}) — not terminated",
                name, pid
            ));
        }

        // Attempt native Windows kill if on Windows
        #[cfg(windows)]
        let kill_result = kill_pid_windows(pid);
        #[cfg(not(windows))]
        let kill_result = if proc.kill_with(Signal::Term).unwrap_or(false) || proc.kill() {
            Ok(())
        } else {
            Err(anyhow::anyhow!("Graceful/Standard kill failed"))
        };

        if kill_result.is_ok() {
            // Remove from flagged list
            if let Ok(mut flagged) = state.flagged_pids.lock() {
                flagged.retain(|&p| p != pid);
            }

            // Emit CRITICAL alert for dashboard popup (same format as simulate_critical_threat)
            let threat = serde_json::json!({
                "level": "CRITICAL",
                "pid": pid,
                "process": name.clone(),
                "file": "",
                "action": "PROCESS_TERMINATED",
                "entropy": 0.0,
                "velocity": 0,
                "timestamp": timestamp_now()
            });
            let _ = app.emit("THREAT_DETECTED", &threat);

            // Notify frontend the process was killed
            let _ = app.emit(
                "PROCESS_KILLED",
                serde_json::json!({
                    "pid": pid,
                    "process": name,
                    "timestamp": timestamp_now(),
                }),
            );

            log::info!("[KillSwitch] Successfully terminated {name} (PID {pid})");
            Ok(format!("Terminated {name} (PID {pid})"))
        } else {
            Err(format!(
                "Failed to kill {name} (PID {pid}) — error: {:?}",
                kill_result.err()
            ))
        }
    } else {
        // Process no longer exists — clean up our list anyway
        if let Ok(mut flagged) = state.flagged_pids.lock() {
            flagged.retain(|&p| p != pid);
        }
        Err(format!(
            "PID {pid} not found — process may have already exited"
        ))
    }
}

/// Return the current list of PIDs flagged as suspicious.
#[tauri::command]
pub fn get_flagged_pids(state: tauri::State<'_, Arc<WatcherState>>) -> Vec<u32> {
    state
        .flagged_pids
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Manually trigger a simulated alert (useful for demo / testing).
#[tauri::command]
pub fn simulate_alert(app: AppHandle) -> Result<(), String> {
    let alert = SecurityAlert {
        process: "demo_ransomware.exe".into(),
        pid: 9999,
        path: "C:\\Users\\DELL\\Documents\\important.docx".into(),
        entropy: 7.94,
        timestamp: timestamp_now(),
        score: 10,
        reasons: vec!["Simulated alert".into()],
    };
    app.emit("threat-detected", &alert)
        .map_err(|e| format!("Emit failed: {e}"))
}

/// Simulate a CRITICAL threat for testing the rapid response system.
#[tauri::command]
pub fn simulate_critical_threat(app: AppHandle) -> Result<(), String> {
    log::warn!("[TEST] Simulating CRITICAL threat detection...");

    let threat = serde_json::json!({
        "level": "CRITICAL",
        "pid": 12345,
        "process": "test_ransomware.exe",
        "file": "C:\\Users\\DELL\\Documents\\secret.docx",
        "action": "HIGH_ENTROPY_ENCRYPTION",
        "entropy": 7.95,
        "velocity": 45,
        "timestamp": timestamp_now()
    });

    app.emit("THREAT_DETECTED", &threat)
        .map_err(|e| format!("Emit failed: {e}"))
}

/// Simulate a HIGH threat for testing.
#[tauri::command]
pub fn simulate_high_threat(app: AppHandle) -> Result<(), String> {
    log::warn!("[TEST] Simulating HIGH threat detection...");

    let threat = serde_json::json!({
        "level": "HIGH",
        "pid": 12346,
        "process": "suspicious_process.exe",
        "file": "C:\\Users\\DELL\\Downloads\\file.zip",
        "action": "RAPID_FILE_MODIFICATION",
        "entropy": 7.2,
        "velocity": 35,
        "timestamp": timestamp_now()
    });

    app.emit("THREAT_DETECTED", &threat)
        .map_err(|e| format!("Emit failed: {e}"))
}

/// Simulate a MEDIUM threat for testing.
#[tauri::command]
pub fn simulate_medium_threat(app: AppHandle) -> Result<(), String> {
    log::info!("[TEST] Simulating MEDIUM threat detection...");

    let threat = serde_json::json!({
        "level": "MEDIUM",
        "pid": 12347,
        "process": "unknown_app.exe",
        "file": "C:\\Users\\DELL\\Documents\\readme.txt",
        "action": "EXTENSION_CHANGE_SUSPICION",
        "entropy": 6.8,
        "velocity": 15,
        "timestamp": timestamp_now()
    });

    app.emit("THREAT_DETECTED", &threat)
        .map_err(|e| format!("Emit failed: {e}"))
}

// ─── Self-Defense ────────────────────────────────────────────────────────────

/// Elevate the current process to HIGH priority class on Windows.
/// This ensures the watcher cannot be starved of CPU by a ransomware
/// process that's burning through disk I/O.
#[cfg(windows)]
pub fn elevate_priority() {
    use windows::Win32::System::Threading::{
        GetCurrentProcess, SetPriorityClass, HIGH_PRIORITY_CLASS,
    };

    unsafe {
        let handle = GetCurrentProcess();
        match SetPriorityClass(handle, HIGH_PRIORITY_CLASS) {
            Ok(_) => log::info!("[SelfDefense] Process priority elevated to HIGH"),
            Err(e) => log::warn!("[SelfDefense] Could not elevate priority: {e}"),
        }
    }
}

#[cfg(not(windows))]
pub fn elevate_priority() {
    log::info!("[SelfDefense] Priority elevation not implemented on this platform");
}

// ─── Windows Native Kill ───────────────────────────────────────────────────

#[cfg(windows)]
pub fn kill_pid_windows(pid: u32) -> AnyResult<()> {
    unsafe {
        let handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        if handle.is_invalid() {
            return Err(anyhow!("Failed to open process for termination"));
        }
        TerminateProcess(handle, 1)?;
        CloseHandle(handle)?;
    }
    Ok(())
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn timestamp_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    let days = secs / 86400;
    let (year, month, day) = epoch_days_to_date(days);
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

fn epoch_days_to_date(days: u64) -> (u64, u64, u64) {
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
