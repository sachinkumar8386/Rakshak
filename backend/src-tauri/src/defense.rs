use sysinfo::{Pid, System};
use std::process;
use anyhow::{Result, anyhow};

/// Hardcoded list of process names that should NEVER be killed or flagged by Rakshak.
/// This includes core system processes, development tools, and parts of the Rakshak UI.
const SAFE_PROCESS_NAMES: &[&str] = &[
    "tauri-app",
    "rakshak",
    "rakshak_project",
    "webview",
    "webviewhost",
    "node",
    "vite",
    "npm",
    "cargo",
    "rustc",
    "code",
    "vscode",
    "cursor",
    "antigravity",
    "gemini",
    "explorer",
    "dwm",
    "csrss",
    "svchost",
    "lsass",
    "winlogon",
    "smss.exe",
    "wininit.exe",
    "services.exe",
    "searchhost.exe",
    "searchindexer.exe",
    "shellexperiencehost.exe",
    "startmenuexperiencehost.exe",
    "taskmgr.exe",
    "systemsettings.exe",
    "runtimebroker.exe",
];

/// Returns true if the process is considered "Safe" and should be ignored by the detection engine.
pub fn is_protected(pid: u32, name: &str, sys: &System) -> bool {
    let self_pid = process::id();
    
    // 1. Never kill self. System core (PID 0-4) is safe UNLESS it's an 'unknown' reporter (unresolved PID)
    if pid == self_pid || (pid <= 4 && name != "unknown") {
        return true;
    }

    let name_lower = name.to_lowercase();

    // 2. Check hardcoded safe list
    if SAFE_PROCESS_NAMES.iter().any(|&safe| name_lower.contains(safe)) {
        return true;
    }

    // 3. Protect the parent process chain (IDE, Shell, etc. that launched us)
    if let Some(proc) = sys.process(Pid::from_u32(pid)) {
        // If the process is our parent, it's safe
        if let Some(self_proc) = sys.process(Pid::from_u32(self_pid)) {
            if let Some(parent_pid) = self_proc.parent() {
                if Pid::from_u32(pid) == parent_pid {
                    log::info!("[Defense] Protected parent process: {} ({})", name, pid);
                    return true;
                }
            }
        }
        
        // Also protect children of Rakshak (e.g. sidecars, though we don't have many)
        if let Some(curr_parent) = proc.parent() {
            if curr_parent.as_u32() == self_pid {
                return true;
            }
        }
    }

    false
}

/// Isolate the host by blocking all inbound and outbound traffic via Windows Firewall (netsh).
#[cfg(windows)]
pub fn isolate_host_windows() -> anyhow::Result<()> {
    log::error!("[Defense] 🔥 ISOLATING HOST: Blocking all network traffic");
    let output = std::process::Command::new("netsh")
        .args(["advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"])
        .output()?;
    
    if output.status.success() {
        Ok(())
    } else {
        Err(anyhow::anyhow!("Firewall isolation failed: {}", String::from_utf8_lossy(&output.stderr)))
    }
}
