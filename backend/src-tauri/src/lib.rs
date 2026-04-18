mod entropy;
mod file_monitor;
mod rapid_detector;

use std::sync::Arc;
use tauri::{Emitter, Manager};

#[cfg(windows)]
fn register_startup() {
    use windows::Win32::System::Registry::{
        RegCreateKeyExW, RegSetValueExW, HKEY_CURRENT_USER, KEY_WRITE, REG_OPTION_NON_VOLATILE,
        REG_SZ,
    };

    if let Ok(exe_path) = std::env::current_exe() {
        let path_str = exe_path.to_string_lossy().to_string();
        let subkey: Vec<u16> = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\0"
            .encode_utf16()
            .collect();
        let value_name: Vec<u16> = "Rakshak\0".encode_utf16().collect();
        let data: Vec<u16> = format!("\"{path_str}\" --minimized\0")
            .encode_utf16()
            .collect();

        unsafe {
            let mut hkey = windows::Win32::System::Registry::HKEY(std::ptr::null_mut());
            if RegCreateKeyExW(
                HKEY_CURRENT_USER,
                windows::core::PCWSTR(subkey.as_ptr()),
                0,
                None,
                REG_OPTION_NON_VOLATILE,
                KEY_WRITE,
                None,
                &mut hkey,
                None,
            )
            .is_ok()
            {
                let _ = RegSetValueExW(
                    hkey,
                    windows::core::PCWSTR(value_name.as_ptr()),
                    0,
                    REG_SZ,
                    Some(std::slice::from_raw_parts(
                        data.as_ptr() as *const u8,
                        data.len() * 2,
                    )),
                );
                let _ = windows::Win32::System::Registry::RegCloseKey(hkey);
            }
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("debug"))
        .format_timestamp_millis()
        .init();

    log::info!("Rakshak [Rapid Detection Engine] starting...");

    #[cfg(windows)]
    register_startup();

    let monitor_state = Arc::new(file_monitor::MonitorState::new());
    let monitor_clone = monitor_state.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(monitor_state)
        .invoke_handler(tauri::generate_handler![
            get_detection_scores,
            get_telemetry,
            clear_alert_history,
            get_alert_history,
            simulate_critical_threat,
            simulate_high_threat,
            simulate_medium_threat,
            reset_detection_state,
        ])
        .setup(move |app| {
            #[cfg(windows)]
            if std::env::args().any(|arg| arg == "--minimized") {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.hide();
                }
            }

            setup_tray(app)?;
            file_monitor::spawn_monitor(app.handle(), monitor_clone.clone());

            log::info!(
                "Rakshak Rapid Detection active - protecting {} dirs",
                file_monitor::PROTECTED_DIRS.len()
            );
            Ok(())
        })
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
            }
        })
        .run(tauri::generate_context!())
        .expect("error while running Rakshak");
}

fn setup_tray(app: &mut tauri::App) -> Result<(), Box<dyn std::error::Error>> {
    use tauri::menu::{Menu, MenuItem};
    use tauri::tray::TrayIconBuilder;

    let quit = MenuItem::with_id(app, "quit", "Quit Rakshak", true, None::<&str>)?;
    let show = MenuItem::with_id(app, "show", "Show Dashboard", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    let _tray = TrayIconBuilder::new()
        .menu(&menu)
        .on_menu_event(|app: &tauri::AppHandle, event: tauri::menu::MenuEvent| {
            match event.id.as_ref() {
                "quit" => {
                    app.exit(0);
                }
                "show" => {
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
                _ => {}
            }
        })
        .on_tray_icon_event(
            |tray: &tauri::tray::TrayIcon, event: tauri::tray::TrayIconEvent| {
                if let tauri::tray::TrayIconEvent::Click { .. } = event {
                    let app = tray.app_handle();
                    if let Some(window) = app.get_webview_window("main") {
                        let _ = window.show();
                        let _ = window.set_focus();
                    }
                }
            },
        )
        .build(app)?;

    Ok(())
}

#[tauri::command]
fn get_detection_scores(
    state: tauri::State<'_, Arc<file_monitor::MonitorState>>,
) -> Vec<rapid_detector::ProcessScore> {
    state
        .detector
        .lock()
        .map(|d| d.get_scores())
        .unwrap_or_default()
}

#[tauri::command]
fn reset_detection_state(state: tauri::State<'_, Arc<file_monitor::MonitorState>>) {
    state.ransomware_detected.store(false, std::sync::atomic::Ordering::SeqCst);
    state.popup_alert_count.store(0, std::sync::atomic::Ordering::SeqCst);
    state.process_killed.store(false, std::sync::atomic::Ordering::SeqCst);
    state.scan_count.store(0, std::sync::atomic::Ordering::SeqCst);
    if let Ok(mut det) = state.detector.lock() {
        det.killed_pids_mut().clear();
        det.processes_mut().clear();
    }
    log::info!("[RAKSHAK] Detection state reset - ready for new tests");
}

#[tauri::command]
fn clear_alert_history(state: tauri::State<'_, Arc<file_monitor::MonitorState>>) {
    if let Ok(mut det) = state.detector.lock() {
        det.killed_pids_mut().clear();
        det.processes_mut().clear();
    }
}

#[derive(serde::Serialize)]
struct Telemetry {
    total_events: u64,
    flagged_events: u64,
    active_processes: usize,
    uptime_seconds: u64,
}

#[tauri::command]
fn get_telemetry(state: tauri::State<'_, Arc<file_monitor::MonitorState>>) -> Telemetry {
    Telemetry {
        total_events: state.total_events.lock().map(|m| *m).unwrap_or(0),
        flagged_events: state.flagged_count.lock().map(|m| *m).unwrap_or(0),
        active_processes: state
            .detector
            .lock()
            .map(|d| d.get_scores().len())
            .unwrap_or(0),
        uptime_seconds: 0,
    }
}

#[tauri::command]
fn get_alert_history() -> Vec<serde_json::Value> {
    vec![]
}

#[tauri::command]
fn simulate_critical_threat(app: tauri::AppHandle) {
    let _ = app.emit(
        "THREAT_DETECTED",
        serde_json::json!({
            "level": "CRITICAL",
            "pid": 9999,
            "process": "test_ransomware.exe",
            "path": "C:\\Users\\DELL\\Documents\\test.txt",
            "action": "SIMULATED",
            "entropy": 9.5,
            "velocity": 50.0,
            "timestamp": chrono_lite_now(),
        }),
    );
}

#[tauri::command]
fn simulate_high_threat(app: tauri::AppHandle) {
    let _ = app.emit(
        "THREAT_DETECTED",
        serde_json::json!({
            "level": "HIGH",
            "pid": 8888,
            "process": "test_suspicious.exe",
            "path": "C:\\Users\\DELL\\Downloads\\test.txt",
            "action": "SIMULATED",
            "entropy": 7.0,
            "velocity": 20.0,
            "timestamp": chrono_lite_now(),
        }),
    );
}

#[tauri::command]
fn simulate_medium_threat(app: tauri::AppHandle) {
    let _ = app.emit(
        "THREAT_DETECTED",
        serde_json::json!({
            "level": "MEDIUM",
            "pid": 7777,
            "process": "test_medium.exe",
            "path": "C:\\Users\\DELL\\Documents\\test.txt",
            "action": "SIMULATED",
            "entropy": 5.0,
            "velocity": 5.0,
            "timestamp": chrono_lite_now(),
        }),
    );
}

fn chrono_lite_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:?}", now)
}
