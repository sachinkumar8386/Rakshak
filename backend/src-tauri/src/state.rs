use crate::detection::ProcessScore;
use crate::watcher::SecurityAlert;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

#[derive(Serialize, Deserialize, Clone)]
pub struct AppSettings {
    pub engine_enabled: bool,
    pub honeypots_enabled: bool,
    pub watchdog_enabled: bool,
    pub auto_snapshot: bool,
    pub whitelist: String,
}

impl Default for AppSettings {
    fn default() -> Self {
        Self {
            engine_enabled: true,
            honeypots_enabled: true,
            watchdog_enabled: true,
            auto_snapshot: false,
            whitelist: "chrome.exe, code.exe".to_string(),
        }
    }
}

/// A record of a process that performed file I/O in a monitored directory.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IoProcessEntry {
    pub pid: u32,
    pub name: String,
    pub path: String,
    pub timestamp: String,
}

/// Rolling buffer capacity
const IO_BUFFER_CAP: usize = 50;

pub struct AppState {
    pub settings: Arc<Mutex<AppSettings>>,
    pub alert_history: Arc<Mutex<Vec<SecurityAlert>>>,
    /// Rolling buffer of the last 50 processes that performed file I/O
    pub io_buffer: Arc<Mutex<VecDeque<IoProcessEntry>>>,
    /// Multi-signal detection engine
    pub detection_engine: Arc<Mutex<crate::detection::DetectionEngine>>,
    /// Shared system state refreshed background every 200ms
    pub sys: Arc<std::sync::RwLock<sysinfo::System>>,
    /// High-speed cache for path -> PID resolution
    pub pid_cache:
        Arc<std::sync::RwLock<std::collections::HashMap<std::path::PathBuf, (u32, String)>>>,
}

impl AppState {
    pub fn new() -> Self {
        use sysinfo::{ProcessRefreshKind, RefreshKind};
        let mut sys = sysinfo::System::new_with_specifics(
            RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
        );
        sys.refresh_processes(sysinfo::ProcessesToUpdate::All, true);

        Self {
            settings: Arc::new(Mutex::new(AppSettings::default())),
            alert_history: Arc::new(Mutex::new(Vec::new())),
            io_buffer: Arc::new(Mutex::new(VecDeque::with_capacity(IO_BUFFER_CAP))),
            detection_engine: Arc::new(Mutex::new(crate::detection::DetectionEngine::new())),
            sys: Arc::new(std::sync::RwLock::new(sys)),
            pid_cache: Arc::new(std::sync::RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Push a new I/O process entry into the rolling buffer.
    /// Automatically evicts the oldest entry when capacity is exceeded.
    pub fn record_io_process(&self, entry: IoProcessEntry) {
        if let Ok(mut buf) = self.io_buffer.lock() {
            if buf.len() >= IO_BUFFER_CAP {
                buf.pop_front();
            }
            buf.push_back(entry);
        }
    }
}

#[tauri::command]
pub fn get_settings(state: tauri::State<'_, Arc<AppState>>) -> AppSettings {
    state.settings.lock().unwrap().clone()
}

#[tauri::command]
pub fn update_settings(new_settings: AppSettings, state: tauri::State<'_, Arc<AppState>>) {
    let mut s = state.settings.lock().unwrap();
    *s = new_settings;
}

#[tauri::command]
pub fn get_alert_history(state: tauri::State<'_, Arc<AppState>>) -> Vec<SecurityAlert> {
    state.alert_history.lock().unwrap().clone()
}

#[tauri::command]
pub fn clear_alert_history(state: tauri::State<'_, Arc<AppState>>) {
    state.alert_history.lock().unwrap().clear();
}

#[tauri::command]
pub fn toggle_layer(layer: String, enabled: bool, state: tauri::State<'_, Arc<AppState>>) {
    let mut s = state.settings.lock().unwrap();
    match layer.as_str() {
        "engine" => s.engine_enabled = enabled,
        "honeypots" => s.honeypots_enabled = enabled,
        "watchdog" => s.watchdog_enabled = enabled,
        _ => log::warn!("Unknown layer toggled: {}", layer),
    }
}

#[tauri::command]
pub fn get_detection_scores(state: tauri::State<'_, Arc<AppState>>) -> Vec<ProcessScore> {
    state.detection_engine.lock().unwrap().get_scores()
}
