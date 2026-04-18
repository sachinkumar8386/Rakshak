use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use notify::{Config, Event, EventKind, RecursiveMode, Watcher};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};
use tauri::{AppHandle, Emitter};

use crate::detection::{deploy_honeypots, ResponseAction};
use crate::entropy::fast_file_entropy;
use crate::state;

const ENTROPY_THRESHOLD: f64 = 7.5;
const RATE_LIMIT_WINDOW_MS: u64 = 1000;
const RATE_LIMIT_MAX_FILES: usize = 5;

#[derive(Clone, serde::Serialize, serde::Deserialize, Debug)]
pub struct SecurityAlert {
    pub process: String,
    pub pid: u32,
    pub path: String,
    pub entropy: f64,
    pub timestamp: String,
    #[serde(default)]
    pub score: u32,
    #[serde(default)]
    pub reasons: Vec<String>,
}

pub struct WatcherState {
    pub flagged_pids: Arc<Mutex<Vec<u32>>>,
    pub isolated_pids: Arc<Mutex<HashSet<u32>>>,
    pub detection_count: Arc<Mutex<u64>>,
}

pub struct RansomDetector {
    pub process_file_counts: HashMap<u32, (usize, Instant)>,
    pub sys: Arc<std::sync::Mutex<sysinfo::System>>,
}

impl RansomDetector {
    pub fn new() -> Self {
        Self {
            process_file_counts: HashMap::new(),
            sys: Arc::new(std::sync::Mutex::new(sysinfo::System::new_all())),
        }
    }

    pub fn get_process_name(&mut self, pid: u32) -> String {
        if let Ok(mut sys) = self.sys.lock() {
            sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            if let Some(p) = sys.process(sysinfo::Pid::from_u32(pid)) {
                return p.name().to_string_lossy().to_string();
            }
        }
        format!("PID:{}", pid)
    }

    fn get_file_velocity(&mut self, pid: u32) -> usize {
        let now = Instant::now();

        // Clean old entries and get velocity
        self.process_file_counts
            .retain(|_, (_, ts)| now.duration_since(*ts) < Duration::from_millis(500));

        self.process_file_counts
            .get(&pid)
            .map(|(c, _)| *c)
            .unwrap_or(0)
    }

    fn record_file_event(&mut self, pid: u32) {
        let now = Instant::now();
        let entry = self.process_file_counts.entry(pid).or_insert((0, now));
        if now.duration_since(entry.1) < Duration::from_millis(500) {
            entry.0 += 1;
        } else {
            entry.0 = 1;
            entry.1 = now;
        }
    }
}

pub fn spawn_watcher(
    app_handle: &AppHandle,
    state: Arc<WatcherState>,
    app_state: Arc<state::AppState>,
) {
    let app = app_handle.clone();
    let app_state_clone = app_state.clone();
    let flagged_pids = state.flagged_pids.clone();
    let detection_count = state.detection_count.clone();

    thread::spawn(move || {
        log::info!("Rakshak: Starting file system watcher...");

        let mut detector = RansomDetector::new();

        let directories_to_watch = get_protected_directories();

        log::info!(
            "Watching {} directories: {:?}",
            directories_to_watch.len(),
            directories_to_watch
        );

        if let Ok(settings) = app_state_clone.settings.lock() {
            if settings.honeypots_enabled {
                log::info!("[Watcher] Deploying honeypot files...");
                let honeypot_paths = deploy_honeypots(&directories_to_watch);
                if let Ok(mut engine) = app_state_clone.detection_engine.lock() {
                    for path in &honeypot_paths {
                        engine.register_honeypot(path.clone());
                    }
                }
                log::info!("[Watcher] {} honeypots deployed", honeypot_paths.len());
            }
        }

        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = notify::recommended_watcher(tx).expect("Failed to create watcher");
        watcher
            .configure(
                Config::default()
                    .with_poll_interval(Duration::from_millis(100)) // Very fast polling
                    .with_compare_contents(false),
            )
            .expect("Failed to configure watcher");

        for dir in &directories_to_watch {
            if dir.exists() {
                if let Err(e) = watcher.watch(dir, RecursiveMode::Recursive) {
                    log::warn!("Failed to watch {}: {}", dir.display(), e);
                } else {
                    log::info!("[Watcher] Now watching: {}", dir.display());
                }
            } else {
                log::warn!("[Watcher] Directory does not exist: {}", dir.display());
            }
        }

        log::info!("File watcher ready. Monitoring for ransomware activity...");

        let mut now = Instant::now();

        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(event)) => {
                    // Process the event
                    if let Some(alert) = process_fs_event(
                        &event,
                        &mut detector,
                        &app,
                        &app_state_clone,
                        &flagged_pids,
                        &detection_count,
                    ) {
                        let _ = app.emit("threat-detected", &alert);
                    }

                    // ALSO: Poll directories for new/changed files periodically
                    // This catches files that may not trigger notify events
                    if now.elapsed() > Duration::from_millis(500) {
                        for dir in &directories_to_watch {
                            if let Ok(entries) = std::fs::read_dir(dir) {
                                for entry in entries.flatten() {
                                    let path = entry.path();
                                    if path.is_file() {
                                        let path_str = path.to_string_lossy().to_lowercase();
                                        // Skip honeypot files
                                        if path_str.contains("_passwords")
                                            || path_str.contains("_recovery")
                                            || path_str.contains("_bank")
                                            || path_str.contains("_tax")
                                            || path_str.contains("aaa_wallet")
                                        {
                                            continue;
                                        }
                                        // Check for suspicious extension changes (.locked, .encrypted, etc.)
                                        if path_str.ends_with(".locked")
                                            || path_str.ends_with(".encrypted")
                                            || path_str.ends_with(".enc")
                                            || path_str.ends_with(".crypt")
                                        {
                                            log::error!(
                                                "[Watcher] >>> DETECTED SUSPICIOUS EXTENSION: {}",
                                                path_str
                                            );
                                            // Read entropy of this file
                                            if let Some(entropy) = fast_file_entropy(&path) {
                                                log::error!("[Watcher] >>> EXTENSION ALERT: {} entropy={:.2}", path.display(), entropy);

                                                if entropy > 6.5 {
                                                    log::error!("[Watcher] >>> CRITICAL: HIGH ENTROPY + EXTENSION CHANGE = KILL");

                                                    // Kill all Python processes and their parent terminals
                                                    kill_python_processes(&app);

                                                    let alert = SecurityAlert {
                                                        process: "SUSPICIOUS_PROCESS".to_string(),
                                                        pid: 0,
                                                        path: path.to_string_lossy().to_string(),
                                                        entropy,
                                                        timestamp: chrono_now(),
                                                        score: 100,
                                                        reasons: vec![
                                                            format!("HIGH ENTROPY: {:.2}", entropy),
                                                            "SUSPICIOUS EXTENSION: .locked"
                                                                .to_string(),
                                                            "CRITICAL THREAT DETECTED".to_string(),
                                                            "PYTHON PROCESS KILLED".to_string(),
                                                        ],
                                                    };
                                                    let _ = app.emit("threat-detected", &alert);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        now = Instant::now();
                    }
                }
                Ok(Err(e)) => {
                    log::error!("Watch error: {:?}", e);
                }
                Err(_) => {
                    // Timeout, continue loop
                }
            }
        }
    });
}

fn process_fs_event(
    event: &Event,
    detector: &mut RansomDetector,
    app: &AppHandle,
    app_state: &Arc<state::AppState>,
    flagged_pids: &Arc<Mutex<Vec<u32>>>,
    detection_count: &Arc<Mutex<u64>>,
) -> Option<SecurityAlert> {
    let paths = &event.paths;
    let pid = event.attrs.process_id().unwrap_or(0);

    // Skip system PIDs
    if pid == 0 || pid <= 4 {
        return None;
    }

    let process_name = detector.get_process_name(pid);

    log::debug!(
        "FS Event: {:?} on {} files, PID={} Process={}",
        event.kind,
        paths.len(),
        pid,
        process_name
    );

    log::info!(
        "[Watcher] File event detected: {:?} on {} files, PID={}",
        event.kind,
        paths.len(),
        pid
    );

    match &event.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {
            log::warn!(
                "[Watcher] >>> RECEIVED {} FILE EVENTS from PID {}",
                paths.len(),
                pid
            );
            for path in paths {
                log::warn!("[Watcher] >>> Processing: {}", path.display());
                let result = analyze_file(
                    path,
                    pid,
                    &process_name,
                    detector,
                    app,
                    app_state,
                    flagged_pids,
                    detection_count,
                );
                if let Some(alert) = &result {
                    log::error!(
                        "[Watcher] >>> ALERT TRIGGERED! Process: {} PID: {} Score: {}",
                        alert.process,
                        alert.pid,
                        alert.score
                    );
                    return result;
                }
                log::info!("[Watcher] No alert for this file");
            }
        }
        _ => {
            log::debug!("[Watcher] Ignoring event type: {:?}", event.kind);
        }
    }

    None
}

fn analyze_file(
    path: &PathBuf,
    pid: u32,
    process_name: &str,
    detector: &mut RansomDetector,
    app: &AppHandle,
    app_state: &Arc<state::AppState>,
    flagged_pids: &Arc<Mutex<Vec<u32>>>,
    detection_count: &Arc<Mutex<u64>>,
) -> Option<SecurityAlert> {
    let path_str = path.to_string_lossy().to_lowercase();
    log::info!("[Watcher] Analyzing path: {}", path_str);

    // Remove overly restrictive filters - only filter system temp
    if path_str.contains("\\appdata\\local\\temp\\") || path_str.contains("\\windows\\") {
        log::info!("[Watcher] FILTERED (system path): {}", path_str);
        return None;
    }

    // Record this file event to track velocity
    detector.record_file_event(pid);

    let velocity = detector.get_file_velocity(pid);
    let extension_changed = has_suspicious_extension(&path_str);

    let is_honeypot = app_state
        .detection_engine
        .lock()
        .map(|e| e.is_honeypot(path))
        .unwrap_or(false);

    log::warn!("[Watcher] Computing entropy for: {}", path.display());

    // Calculate entropy - if file doesn't exist or can't read, assume suspicious
    let entropy = match fast_file_entropy(path) {
        Some(e) => {
            log::warn!(
                "[Watcher] File: {} | Entropy: {:.2} | Velocity: {}",
                path.display(),
                e,
                velocity
            );
            e
        }
        None => {
            log::warn!(
                "[Watcher] Could not read entropy for {} - using suspicious default",
                path.display()
            );
            7.5 // Assume encrypted if we can't read (file might be locked by attacker)
        }
    };

    if entropy > 6.5 {
        log::warn!("[Watcher] HIGH ENTROPY DETECTED: {:.2}!", entropy);
    }

    let action =
        ResponseAction::from_decision_matrix(entropy, velocity, extension_changed, is_honeypot);

    log::error!(
            "[Watcher] Decision: Entropy={:.2} Velocity={} ExtensionChanged={} IsHoneypot={} => Action={:?}",
            entropy,
            velocity,
            extension_changed,
            is_honeypot,
            action
        );

    match action {
        ResponseAction::KillAndIsolate => {
            log::error!("🚨🚨🚨 CRITICAL: RANSOMWARE DETECTED - KILL & ISOLATE 🚨🚨🚨");
            log::error!(
                "Process: {} (PID: {}) | Entropy: {:.2} | Velocity: {}",
                process_name,
                pid,
                entropy,
                velocity
            );

            let mut reasons = vec![format!("ENTROPY: {:.2}", entropy)];
            if entropy > 6.0 {
                reasons.push("HIGH ENTROPY DETECTED".to_string());
            }
            if velocity >= 10 {
                reasons.push("CRITICAL VELOCITY".to_string());
            }
            if velocity > 30 {
                reasons.push("CRITICAL VELOCITY".to_string());
            }
            if extension_changed {
                reasons.push("EXTENSION CHANGE".to_string());
            }
            if is_honeypot {
                reasons.push("HONEYPOT TRIGGERED".to_string());
            }

            if let Ok(mut count) = detection_count.lock() {
                *count += 1;
            }

            let alert = SecurityAlert {
                process: process_name.to_string(),
                pid,
                path: path.to_string_lossy().to_string(),
                entropy,
                timestamp: chrono_now(),
                score: 100,
                reasons,
            };

            if let Ok(mut hist) = app_state.alert_history.lock() {
                hist.push(alert.clone());
            }

            if let Ok(mut flagged) = flagged_pids.lock() {
                if !flagged.contains(&pid) {
                    flagged.push(pid);
                }
            }

            kill_process_tree(pid);

            let _ = app.emit(
                "THREAT_DETECTED",
                serde_json::json!({
                    "level": "CRITICAL",
                    "pid": pid,
                    "process": process_name,
                    "file": path.to_string_lossy(),
                    "action": "KILL_AND_ISOLATE",
                    "entropy": entropy,
                    "velocity": velocity,
                    "isHoneypot": is_honeypot
                }),
            );

            return Some(alert);
        }
        ResponseAction::Suspend => {
            log::warn!(
                "⚠️ HIGH: Suspicious activity - suspending process {} (PID {})",
                process_name,
                pid
            );
            if let Ok(mut count) = detection_count.lock() {
                *count += 1;
            }

            let alert = SecurityAlert {
                process: process_name.to_string(),
                pid,
                path: path.to_string_lossy().to_string(),
                entropy,
                timestamp: chrono_now(),
                score: 70,
                reasons: vec![
                    format!("HIGH ENTROPY: {:.2}", entropy),
                    format!("VELOCITY: {}", velocity),
                ],
            };

            if let Ok(mut hist) = app_state.alert_history.lock() {
                hist.push(alert.clone());
            }

            let _ = app.emit(
                "THREAT_DETECTED",
                serde_json::json!({
                    "level": "HIGH",
                    "pid": pid,
                    "process": process_name,
                    "file": path.to_string_lossy(),
                    "action": "SUSPEND",
                    "entropy": entropy,
                    "velocity": velocity,
                    "timestamp": chrono_now()
                }),
            );
        }
        ResponseAction::Alert => {
            log::info!(
                "ℹ️ MEDIUM: Alert triggered for {} (PID {})",
                process_name,
                pid
            );

            let alert = SecurityAlert {
                process: process_name.to_string(),
                pid,
                path: path.to_string_lossy().to_string(),
                entropy,
                timestamp: chrono_now(),
                score: 50,
                reasons: vec![
                    format!("ENTROPY: {:.2}", entropy),
                    format!("VELOCITY: {}", velocity),
                ],
            };

            if let Ok(mut hist) = app_state.alert_history.lock() {
                hist.push(alert.clone());
            }

            let _ = app.emit(
                "THREAT_DETECTED",
                serde_json::json!({
                    "level": "MEDIUM",
                    "pid": pid,
                    "process": process_name,
                    "file": path.to_string_lossy(),
                    "action": "ALERT",
                    "entropy": entropy,
                    "velocity": velocity,
                    "timestamp": chrono_now()
                }),
            );
        }
        ResponseAction::Monitor | ResponseAction::Allow => {}
    }

    None
}

fn kill_process(pid: u32) {
    #[cfg(windows)]
    {
        let _ = crate::killswitch::kill_pid_windows(pid);
    }
}

fn kill_process_tree(pid: u32) {
    log::error!("KILLING PROCESS TREE FOR PID {} NOW!", pid);

    #[cfg(windows)]
    {
        let mut sys = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let target_pid = Pid::from_u32(pid);
        let mut children_to_kill: Vec<u32> = Vec::new();

        for (p, process) in sys.processes() {
            if let Some(parent) = process.parent() {
                if parent == target_pid {
                    children_to_kill.push(p.as_u32());
                }
            }
        }

        for child_pid in &children_to_kill {
            log::warn!("Killing child process: PID {}", child_pid);
            kill_process_tree(*child_pid);
        }

        let _ = crate::killswitch::kill_pid_windows(pid);
    }
}

fn has_suspicious_extension(path: &str) -> bool {
    let suspicious = [
        "encrypted",
        "locked",
        "crypt",
        "enc",
        "locky",
        "cerber",
        "zepto",
        "zzzzz",
        "crypto",
        "lockbit",
        "dharma",
        "ryuk",
        "maze",
        "wanna",
        "petya",
        "notpetya",
    ];

    for ext in suspicious {
        if path.ends_with(&format!(".{}", ext)) {
            return true;
        }
    }
    false
}

pub fn get_protected_directories() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    // User directories
    if let Some(home) = dirs::home_dir() {
        dirs.push(home.join("Documents"));
        dirs.push(home.join("Desktop"));
        dirs.push(home.join("Downloads"));
        dirs.push(home.join("Pictures"));
        dirs.push(home.join("Videos"));
        dirs.push(home.join("Music"));

        // Also watch our test directory if it exists
        let test_dir = home.join("Documents").join("rakshak_test");
        if test_dir.exists() {
            dirs.push(test_dir.clone());
            log::info!("[Watcher] Adding test directory: {}", test_dir.display());
        }
    }

    // Windows standard directories
    if let Some(user_profile) = std::env::var_os("USERPROFILE") {
        let home = PathBuf::from(user_profile);
        dirs.push(home.join("Documents"));
        dirs.push(home.join("Desktop"));
        dirs.push(home.join("Downloads"));
    }

    // Remove duplicates and non-existent
    dirs.sort();
    dirs.dedup();
    dirs.retain(|p| p.exists());

    log::info!("[Watcher] Final directories being watched: {:?}", dirs);

    dirs
}

fn chrono_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:?}", now)
}

fn create_critical_alert(
    path: &PathBuf,
    pid: u32,
    process_name: &str,
    entropy: f64,
    score: u32,
) -> SecurityAlert {
    SecurityAlert {
        process: process_name.to_string(),
        pid,
        path: path.to_string_lossy().to_string(),
        entropy,
        timestamp: chrono_now(),
        score,
        reasons: vec![
            format!("HIGH ENTROPY: {:.2}", entropy),
            "SUSPICIOUS EXTENSION: .locked".to_string(),
            "CRITICAL THREAT DETECTED".to_string(),
        ],
    }
}

fn kill_python_processes(app: &AppHandle) {
    log::error!("[Watcher] >>> KILLING PYTHON PROCESSES ONLY!");

    #[cfg(windows)]
    {
        use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

        let mut sys = System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes(ProcessesToUpdate::All, true);

        let python_processes: Vec<(u32, String)> = sys
            .processes()
            .iter()
            .filter(|(_, proc)| {
                let name = proc.name().to_string_lossy().to_lowercase();
                name.contains("python") && !name.contains("pythonw")
            })
            .map(|(pid, proc)| (pid.as_u32(), proc.name().to_string_lossy().to_string()))
            .collect();

        let pythonw_processes: Vec<(u32, String)> = sys
            .processes()
            .iter()
            .filter(|(_, proc)| {
                let name = proc.name().to_string_lossy().to_lowercase();
                name.contains("pythonw")
            })
            .map(|(pid, proc)| (pid.as_u32(), proc.name().to_string_lossy().to_string()))
            .collect();

        let mut total_killed = 0;

        for (python_pid, python_name) in &python_processes {
            log::warn!(
                "[Watcher] Killing Python process: {} (PID {})",
                python_name,
                python_pid
            );
            let _ = crate::killswitch::kill_pid_windows(*python_pid);
            total_killed += 1;

            let _ = app.emit(
                "PROCESS_KILLED",
                serde_json::json!({
                    "pid": python_pid,
                    "process": python_name,
                    "reason": "Ransomware Detection - Python Script",
                    "timestamp": chrono_now(),
                }),
            );

            let _ = app.emit(
                "THREAT_DETECTED",
                serde_json::json!({
                    "level": "CRITICAL",
                    "pid": python_pid,
                    "process": python_name,
                    "file": "",
                    "action": "PYTHON_PROCESS_TERMINATED",
                    "entropy": 0.0,
                    "velocity": 0,
                    "timestamp": chrono_now(),
                }),
            );
        }

        for (python_pid, python_name) in &pythonw_processes {
            log::warn!(
                "[Watcher] Killing Pythonw process: {} (PID {})",
                python_name,
                python_pid
            );
            let _ = crate::killswitch::kill_pid_windows(*python_pid);
            total_killed += 1;

            let _ = app.emit(
                "PROCESS_KILLED",
                serde_json::json!({
                    "pid": python_pid,
                    "process": python_name,
                    "reason": "Ransomware Detection - Background Python Script",
                    "timestamp": chrono_now(),
                }),
            );
        }

        log::error!(
            "[Watcher] >>> Selective termination complete: {} Python process(es) killed",
            total_killed
        );
    }
}
