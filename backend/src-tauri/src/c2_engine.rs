/// C2 Network Correlation Engine
///
/// Scans all active TCP/UDP connections via `netstat2`, cross-references
/// owning PIDs against the rolling I/O buffer (last 50 processes that
/// wrote to monitored directories), and flags any process that has both
/// file-write activity AND an external (non-local) network connection
/// as SUSPICIOUS_C2_ACTIVITY.

use std::net::IpAddr;
use std::sync::Arc;

use netstat2::{
    get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo,
};
use serde::Serialize;
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

use crate::state::AppState;

// ─── Data structures ────────────────────────────────────────────────────────

#[derive(Clone, Serialize)]
pub struct C2AuditResult {
    pub process_name: String,
    pub pid: u32,
    pub remote_ip: String,
    pub remote_port: u16,
    pub protocol: String,
    pub risk_level: String,      // "SUSPICIOUS_C2_ACTIVITY" | "NORMAL"
    pub reason: String,
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Returns true if the IP is a local/private/loopback address.
fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()                                  // 127.x.x.x
                || v4.is_private()                             // 10.x, 172.16-31.x, 192.168.x
                || v4.is_link_local()                          // 169.254.x.x
                || v4.is_unspecified()                         // 0.0.0.0
                || v4.octets()[0] == 100 && v4.octets()[1] >= 64 && v4.octets()[1] <= 127 // CGNAT
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified()
        }
    }
}

/// Look up a process name by PID via sysinfo.
fn process_name_by_pid(sys: &System, pid: u32) -> String {
    use sysinfo::Pid;
    sys.process(Pid::from_u32(pid))
        .map(|p| p.name().to_string_lossy().to_string())
        .unwrap_or_else(|| format!("PID-{pid}"))
}

// ─── Core scan ──────────────────────────────────────────────────────────────

/// Perform a full network audit:
/// 1. Snapshot all TCP/UDP sockets with their owning PIDs.
/// 2. Cross-reference each PID against the rolling I/O buffer.
/// 3. If match + non-local remote IP → SUSPICIOUS_C2_ACTIVITY.
fn scan_network(app_state: &AppState) -> Vec<C2AuditResult> {
    let af = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto = ProtocolFlags::TCP | ProtocolFlags::UDP;

    let sockets = match get_sockets_info(af, proto) {
        Ok(s) => s,
        Err(e) => {
            log::error!("[C2] Failed to enumerate sockets: {e}");
            return Vec::new();
        }
    };

    // Snapshot system processes so we can resolve names
    let mut sys = System::new_with_specifics(
        RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes(ProcessesToUpdate::All, true);

    // Get the set of PIDs from the I/O buffer
    let io_pids: std::collections::HashSet<u32> = {
        let buf = app_state.io_buffer.lock().unwrap();
        buf.iter().map(|entry| entry.pid).collect()
    };

    let mut results: Vec<C2AuditResult> = Vec::new();

    for si in &sockets {
        let (remote_ip, remote_port, protocol) = match &si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp) => {
                (tcp.remote_addr, tcp.remote_port, "TCP")
            }
            ProtocolSocketInfo::Udp(udp) => {
                // UDP is connectionless; use local addr as reference
                (udp.local_addr, udp.local_port, "UDP")
            }
        };

        // Skip sockets with no owning process
        if si.associated_pids.is_empty() {
            continue;
        }

        for &pid in &si.associated_pids {
            // Only flag TCP connections with a real remote endpoint
            if protocol == "UDP" {
                continue; // skip UDP for C2 analysis (no reliable remote info)
            }

            // Skip connections to local/private addresses
            if is_local_ip(&remote_ip) {
                continue;
            }

            // Skip port 0 (not established)
            if remote_port == 0 {
                continue;
            }

            let name = process_name_by_pid(&sys, pid);

            // Check if this PID is in the I/O buffer
            let in_io_buffer = io_pids.contains(&pid);

            let (risk_level, reason) = if in_io_buffer {
                (
                    "SUSPICIOUS_C2_ACTIVITY".to_string(),
                    format!(
                        "Process modified files in monitored dirs AND has active external connection to {}:{}",
                        remote_ip, remote_port
                    ),
                )
            } else {
                (
                    "NORMAL".to_string(),
                    format!("External connection to {}:{} (not in file-I/O buffer)", remote_ip, remote_port),
                )
            };

            results.push(C2AuditResult {
                process_name: name,
                pid,
                remote_ip: remote_ip.to_string(),
                remote_port,
                protocol: protocol.to_string(),
                risk_level,
                reason,
            });
        }
    }

    // Sort: suspicious first, then by PID
    results.sort_by(|a, b| {
        let a_sus = a.risk_level == "SUSPICIOUS_C2_ACTIVITY";
        let b_sus = b.risk_level == "SUSPICIOUS_C2_ACTIVITY";
        b_sus.cmp(&a_sus).then(a.pid.cmp(&b.pid))
    });

    // De-duplicate by (pid, remote_ip, remote_port)
    results.dedup_by(|a, b| a.pid == b.pid && a.remote_ip == b.remote_ip && a.remote_port == b.remote_port);

    results
}

// ─── Tauri command ──────────────────────────────────────────────────────────

#[tauri::command]
pub fn run_network_audit(state: tauri::State<'_, Arc<AppState>>) -> Vec<C2AuditResult> {
    log::info!("[C2] Running network audit…");
    let results = scan_network(&state);
    let suspicious_count = results.iter().filter(|r| r.risk_level == "SUSPICIOUS_C2_ACTIVITY").count();
    log::info!("[C2] Audit complete: {} connections scanned, {} suspicious", results.len(), suspicious_count);
    results
}

/// Clear the rolling I/O buffer used for C2 correlation.
#[tauri::command]
pub fn reset_c2_audit(state: tauri::State<'_, Arc<AppState>>) {
    log::info!("[C2] Resetting I/O buffer and audit state");
    if let Ok(mut buf) = state.io_buffer.lock() {
        buf.clear();
    }
}
