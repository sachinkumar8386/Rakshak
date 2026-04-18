use std::path::PathBuf;
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

pub struct MonitorState {
    pub detector: Arc<Mutex<RapidDetector>>,
    pub total_events: Arc<Mutex<u64>>,
    pub flagged_count: Arc<Mutex<u64>>,
}

impl MonitorState {
    pub fn new() -> Self {
        Self {
            detector: Arc::new(Mutex::new(RapidDetector::new())),
            total_events: Arc::new(Mutex::new(0)),
            flagged_count: Arc::new(Mutex::new(0)),
        }
    }
}

pub fn spawn_monitor(app_handle: &AppHandle, state: Arc<MonitorState>) {
    let app = app_handle.clone();
    let detector = state.detector.clone();
    let total_events = state.total_events.clone();
    let flagged_count = state.flagged_count.clone();

    thread::spawn(move || {
        log::info!("[RAKSHAK] FileMonitor starting...");

        let directories = get_protected_directories();
        log::info!(
            "[RAKSHAK] Monitoring {} directories: {:?}",
            directories.len(),
            directories
        );

        let (tx, rx) = std::sync::mpsc::channel();

        let mut watcher = RecommendedWatcher::new(tx).expect("[RAKSHAK] Failed to create watcher");

        watcher
            .configure(
                Config::default()
                    .with_poll_interval(Duration::from_millis(50))
                    .with_compare_contents(false),
            )
            .expect("[RAKSHAK] Failed to configure watcher");

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
                    if let Some(alert) = process_event(&event, &detector, &total_events) {
                        if let Ok(mut cnt) = flagged_count.lock() {
                            *cnt += 1;
                        }
                        let _ = app.emit("THREAT_DETECTED", &alert);
                        let _ = app.emit(
                            "PROCESS_KILLED",
                            serde_json::json!({
                                "pid": alert.pid,
                                "process": alert.process,
                                "action": alert.action,
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
) -> Option<crate::rapid_detector::ThreatAlert> {
    let pid = event.attrs.process_id().unwrap_or(0);
    if pid == 0 || pid <= 4 {
        return None;
    }

    if let Ok(mut cnt) = total_events.lock() {
        *cnt += 1;
    }

    let is_write = matches!(
        event.kind,
        EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
    );
    let is_read = matches!(event.kind, EventKind::Access(_));

    for path in &event.paths {
        if path.is_dir() {
            continue;
        }
        if is_system_path(path) {
            continue;
        }

        let alert = if is_write {
            if let Ok(mut det) = detector.lock() {
                det.record_write(pid, path)
            } else {
                None
            }
        } else if is_read {
            if let Ok(mut det) = detector.lock() {
                det.record_read(pid, path)
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
