mod file_monitor;
mod rapid_detector;

use std::sync::{Arc, Mutex};
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format_timestamp_millis()
        .init();

    log::info!("Rakshak [Rapid Detection Engine] starting...");

    let monitor_state = Arc::new(file_monitor::MonitorState::new());
    let monitor_clone = monitor_state.clone();

    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_notification::init())
        .manage(monitor_state)
        .invoke_handler(tauri::generate_handler![
            get_detection_scores,
            get_monitor_stats,
            clear_alert_history,
        ])
        .setup(move |app| {
            setup_tray(app)?;
            file_monitor::spawn_monitor(app.handle(), monitor_clone.clone());
            log::info!("Rakshak Rapid Detection active");
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
        .on_menu_event(|app: &tauri::AppHandle, event| match event.id.as_ref() {
            "quit" => app.exit(0),
            "show" => {
                if let Some(window) = app.get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let tauri::tray::TrayIconEvent::Click { .. } = event {
                if let Some(window) = tray.app_handle().get_webview_window("main") {
                    let _ = window.show();
                    let _ = window.set_focus();
                }
            }
        })
        .build(app)?;

    Ok(())
}

#[derive(serde::Serialize)]
struct MonitorStats {
    total_events: u64,
    flagged_count: u64,
}

#[tauri::command]
fn get_monitor_stats(state: tauri::State<'_, Arc<file_monitor::MonitorState>>) -> MonitorStats {
    MonitorStats {
        total_events: state.total_events.lock().map(|m| *m).unwrap_or(0),
        flagged_count: state.flagged_count.lock().map(|m| *m).unwrap_or(0),
    }
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
fn clear_alert_history(state: tauri::State<'_, Arc<file_monitor::MonitorState>>) {
    if let Ok(mut det) = state.detector.lock() {
        det.killed_pids_mut().clear();
        det.processes_mut().clear();
    }
}
