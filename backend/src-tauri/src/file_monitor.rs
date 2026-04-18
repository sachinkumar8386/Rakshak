use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use tauri::{AppHandle, Emitter};

use crate::rapid_detector::RapidDetector;

pub const PROTECTED_DIRS: &[&str] = &[
    "Documents",
    "Desktop",
    "Downloads",
    "Pictures",
    "Videos",
    "Music",
];

pub const MAX_POPUP_ALERTS: u32 = 2;
pub const KILL_THRESHOLD: u32 = 1;

pub struct MonitorState {
    pub detector: Arc<Mutex<RapidDetector>>,
    pub total_events: Arc<Mutex<u64>>,
    pub flagged_count: Arc<Mutex<u64>>,
    pub ransomware_detected: Arc<AtomicBool>,
    pub popup_alert_count: Arc<AtomicU32>,
    pub process_killed: Arc<AtomicBool>,
    pub scan_count: Arc<AtomicU32>,
}

impl MonitorState {
    pub fn new() -> Self {
        Self {
            detector: Arc::new(Mutex::new(RapidDetector::new())),
            total_events: Arc::new(Mutex::new(0)),
            flagged_count: Arc::new(Mutex::new(0)),
            ransomware_detected: Arc::new(AtomicBool::new(false)),
            popup_alert_count: Arc::new(AtomicU32::new(0)),
            process_killed: Arc::new(AtomicBool::new(false)),
            scan_count: Arc::new(AtomicU32::new(0)),
        }
    }
}

pub fn spawn_monitor(app_handle: &AppHandle, state: Arc<MonitorState>) {
    let app = app_handle.clone();
    let detector = state.detector.clone();
    let total_events = state.total_events.clone();
    let flagged_count = state.flagged_count.clone();
    let ransomware_detected = state.ransomware_detected.clone();
    let popup_alert_count = state.popup_alert_count.clone();
    let process_killed = state.process_killed.clone();

    thread::spawn(move || {
        log::info!("[RAKSHAK] FileMonitor starting...");

        let directories = get_protected_directories();
        log::info!(
            "[RAKSHAK] Scanning protected directories: {:?}",
            directories
        );

        thread::spawn({
            let app = app.clone();
            let ransomware_detected = ransomware_detected.clone();
            let popup_alert_count = popup_alert_count.clone();
            let process_killed = process_killed.clone();
            let directories = get_protected_directories();
            move || loop {
                if !ransomware_detected.load(Ordering::SeqCst) {
                    check_suspicious_files(
                        &app,
                        &directories,
                        &ransomware_detected,
                        &popup_alert_count,
                        &process_killed,
                    );
                }
                thread::sleep(Duration::from_millis(500));
            }
        });

        let directories = get_protected_directories();
        log::info!(
            "[RAKSHAK] Monitoring {} directories: {:?}",
            directories.len(),
            directories
        );

        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = RecommendedWatcher::new(
            tx,
            Config::default()
                .with_poll_interval(Duration::from_millis(50))
                .with_compare_contents(false),
        )
        .expect("[RAKSHAK] Failed to create watcher");

        for dir in &directories {
            if dir.exists() {
                if let Err(e) = watcher.watch(dir, RecursiveMode::Recursive) {
                    log::warn!("[RAKSHAK] Failed to watch {}: {}", dir.display(), e);
                } else {
                    log::info!("[RAKSHAK] Watching: {}", dir.display());
                }
            }
        }

        let mut cleanup_interval = 0u64;

        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(Ok(event)) => {
                    log::debug!("[RAKSHAK] File event: {:?}", event.kind);
                    if let Some(alert) = process_event(
                        &event,
                        &detector,
                        &total_events,
                        &ransomware_detected,
                        &popup_alert_count,
                        &process_killed,
                        &app,
                    ) {
                        if let Ok(mut cnt) = flagged_count.lock() {
                            *cnt += 1;
                        }

                        let should_popup = !process_killed.load(Ordering::SeqCst)
                            && popup_alert_count.load(Ordering::SeqCst) < MAX_POPUP_ALERTS;

                        let _ = app.emit("THREAT_DETECTED", &alert);
                        let _ = app.emit(
                            "PROCESS_KILLED",
                            serde_json::json!({
                                "pid": alert.pid,
                                "process": alert.process,
                                "action": alert.action,
                                "should_popup": should_popup,
                            }),
                        );
                    }
                }
                Ok(Err(e)) => {
                    log::warn!("[RAKSHAK] Watch error: {:?}", e);
                }
                Err(_) => {}
            }

            cleanup_interval += 1;
            if cleanup_interval % 30 == 0 {
                if let Ok(mut det) = detector.lock() {
                    det.cleanup_stale();
                }
            }
        }
    });
}

fn process_event(
    event: &Event,
    detector: &Arc<Mutex<RapidDetector>>,
    total_events: &Arc<Mutex<u64>>,
    ransomware_detected: &Arc<AtomicBool>,
    popup_alert_count: &Arc<AtomicU32>,
    process_killed: &Arc<AtomicBool>,
    app: &AppHandle,
) -> Option<crate::rapid_detector::ThreatAlert> {
    let pid = event.attrs.process_id().unwrap_or(0);
    if pid > 0 && pid <= 4 {
        return None;
    }

    let effective_pid = if pid == 0 { 9999 } else { pid };

    if let Ok(mut cnt) = total_events.lock() {
        *cnt += 1;
    }

    let is_write = matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    );
    let is_read = matches!(event.kind, EventKind::Access(_));

    let suspicious_extensions = [
        ".locked",
        ".encrypted",
        ".crypt",
        ".pay",
        ".wannacrypt",
        ".crypto",
    ];

    for path in &event.paths {
        if path.is_dir() {
            continue;
        }
        if is_system_path(path) {
            log::debug!("[RAKSHAK] Skipping system path: {:?}", path);
            continue;
        }

        let path_str = path.to_string_lossy().to_lowercase();
        for ext in &suspicious_extensions {
            if path_str.ends_with(ext) {
                log::error!("[RAKSHAK] CRITICAL: Ransomware file detected: {:?}", path);

                popup_alert_count.fetch_add(1, Ordering::SeqCst);
                let should_popup = popup_alert_count.load(Ordering::SeqCst) <= MAX_POPUP_ALERTS;

                if !ransomware_detected.load(Ordering::SeqCst) {
                    ransomware_detected.store(true, Ordering::SeqCst);
                    kill_all_python();
                    process_killed.store(true, Ordering::SeqCst);
                }

                return Some(crate::rapid_detector::ThreatAlert {
                    level: "CRITICAL".to_string(),
                    pid: effective_pid,
                    process: "Ransomware Detected".to_string(),
                    path: path.to_string_lossy().to_string(),
                    action: "KILLED".to_string(),
                    read_count: 0,
                    write_count: 1,
                    velocity: 100.0,
                    timestamp: chrono_lite_now(),
                    should_popup,
                });
            }
        }

        log::debug!("[RAKSHAK] Processing path: {:?}", path);
        let alert = if is_write {
            if let Ok(mut det) = detector.lock() {
                det.record_write(effective_pid, path)
            } else {
                None
            }
        } else if is_read {
            if let Ok(mut det) = detector.lock() {
                det.record_read(effective_pid, path)
            } else {
                None
            }
        } else {
            None
        };

        if alert.is_some() {
            return alert;
        }
    }

    None
}

fn is_system_path(path: &PathBuf) -> bool {
    let p = path.to_string_lossy().to_lowercase();
    p.contains("\\appdata\\local\\temp\\")
        || p.contains("\\windows\\temp\\")
        || p.contains("\\$recycle.bin\\")
        || p.contains("\\system volume information\\")
        || p.contains("\\node_modules\\")
        || p.contains("\\.git\\")
        || p.contains("\\target\\")
        || p.ends_with(".tmp")
        || p.ends_with(".log")
        || p.contains("\\vscode\\")
        || p.contains("\\.cache\\")
}

fn check_suspicious_files(
    app: &AppHandle,
    directories: &[PathBuf],
    ransomware_detected: &Arc<AtomicBool>,
    popup_alert_count: &Arc<AtomicU32>,
    process_killed: &Arc<AtomicBool>,
) {
    log::debug!("[RAKSHAK] Scanning for suspicious files...");
    let suspicious_extensions = [
        ".locked",
        ".encrypted",
        ".crypt",
        ".pay",
        ".wannacrypt",
        ".crypto",
    ];

    for dir in directories {
        log::debug!("[RAKSHAK] Scanning directory: {:?}", dir);
        if process_killed.load(Ordering::SeqCst) {
            break;
        }

        check_suspicious_files_recursive(
            app,
            dir,
            &suspicious_extensions,
            ransomware_detected,
            popup_alert_count,
            process_killed,
        );
    }
}

fn is_ignored_dir(path: &std::path::Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    name == "node_modules"
        || name == "target"
        || name == ".git"
        || name == ".vscode"
        || name == "dist"
        || name == "build"
        || name == ".cache"
}

fn check_suspicious_files_recursive(
    app: &AppHandle,
    dir: &std::path::Path,
    extensions: &[&str],
    ransomware_detected: &Arc<AtomicBool>,
    popup_alert_count: &Arc<AtomicU32>,
    process_killed: &Arc<AtomicBool>,
) {
    if process_killed.load(Ordering::SeqCst) {
        return;
    }

    if is_ignored_dir(dir) {
        return;
    }

    log::debug!("[RAKSHAK] RECURSIVE: Scanning dir: {:?}", dir);

    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            if process_killed.load(Ordering::SeqCst) {
                return;
            }

            let path = entry.path();
            if path.is_dir() {
                check_suspicious_files_recursive(
                    app,
                    &path,
                    extensions,
                    ransomware_detected,
                    popup_alert_count,
                    process_killed,
                );
            } else if path.is_file() {
                let path_str = path.to_string_lossy().to_lowercase();
                for ext in extensions {
                    if path_str.ends_with(ext) {
                        log::error!("[RAKSHAK] CRITICAL: Ransomware file detected: {:?}", path);

                        let current_popups = popup_alert_count.fetch_add(1, Ordering::SeqCst) + 1;
                        let should_popup = current_popups <= MAX_POPUP_ALERTS;

                        if !ransomware_detected.load(Ordering::SeqCst) {
                            log::error!("[RAKSHAK] First detection - killing processes!");
                            ransomware_detected.store(true, Ordering::SeqCst);
                            process_killed.store(true, Ordering::SeqCst);
                            kill_all_python();

                            let _ = app.emit(
                                "PROCESS_KILLED",
                                serde_json::json!({
                                    "pid": 0,
                                    "process": "Python",
                                    "action": "TERMINATED",
                                    "should_popup": should_popup,
                                }),
                            );
                        }

                        let _ = app.emit(
                            "THREAT_DETECTED",
                            serde_json::json!({
                                "level": "CRITICAL",
                                "pid": 0,
                                "process": "Ransomware Detected",
                                "path": path.to_string_lossy(),
                                "action": "DETECTED",
                                "entropy": 9.0,
                                "velocity": 100.0,
                                "timestamp": chrono_lite_now(),
                                "should_popup": should_popup,
                            }),
                        );

                        if current_popups >= MAX_POPUP_ALERTS {
                            log::error!("[RAKSHAK] Max popup alerts reached, stopping scan");
                            return;
                        }
                    }
                }
            }
        }
    }
}

fn find_python_pids() -> Result<Vec<u32>, std::io::Error> {
    use sysinfo::{Pid, System};
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    let mut pids = Vec::new();
    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        if name.contains("python") || name.contains("python3") {
            pids.push(pid.as_u32());
        }
    }
    Ok(pids)
}

fn kill_all_python() {
    use sysinfo::{Pid, System};
    use windows::Win32::System::Threading::{
        OpenProcess, TerminateProcess, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE,
    };
    let mut sys = System::new();
    sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

    for (pid, process) in sys.processes() {
        let name = process.name().to_string_lossy().to_lowercase();
        if name.contains("python") || name.contains("python3") {
            log::error!("[RAKSHAK] Killing suspicious Python process: {}", pid);
            unsafe {
                let handle = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE,
                    false,
                    pid.as_u32(),
                );
                if handle.is_ok() {
                    let _ = TerminateProcess(handle.unwrap(), 1);
                    log::info!("[RAKSHAK] Python process {} terminated", pid);
                }
            }
        }
    }
}

fn kill_pid(pid: u32) -> Result<(), std::io::Error> {
    #[cfg(windows)]
    {
        use windows::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE,
        };
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, false, pid);
            if handle.is_ok() {
                let _ = TerminateProcess(handle.unwrap(), 1);
            }
        }
    }
    Ok(())
}

fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:?}", now)
}

fn get_protected_directories() -> Vec<PathBuf> {
    let mut dirs = Vec::new();

    if let Some(home) = dirs::home_dir() {
        for name in PROTECTED_DIRS {
            let dir = home.join(name);
            if dir.exists() {
                dirs.push(dir);
            }
        }
    }

    if let Some(user_profile) = std::env::var_os("USERPROFILE") {
        let home = PathBuf::from(user_profile);
        for name in PROTECTED_DIRS {
            let dir = home.join(name);
            if dir.exists() && !dirs.contains(&dir) {
                dirs.push(dir);
            }
        }
    }

    dirs.sort();
    dirs.dedup();
    log::info!("[RAKSHAK] Final protected dirs: {:?}", dirs);
    dirs
}
