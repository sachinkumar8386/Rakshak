use serde::Serialize;
use std::sync::Mutex;
use sysinfo::{CpuRefreshKind, MemoryRefreshKind, ProcessesToUpdate, RefreshKind, System};

#[derive(Serialize, Clone)]
pub struct SystemTelemetry {
    pub cpu_usage: f32,
    pub ram_usage: f32,
    pub disk_io: f32,
    pub network_io: f32,
    pub active_processes: usize,
}

pub struct TelemetryState(pub Mutex<System>);

impl TelemetryState {
    pub fn new() -> Self {
        Self(Mutex::new(System::new_with_specifics(
            RefreshKind::nothing()
                .with_cpu(CpuRefreshKind::everything())
                .with_memory(MemoryRefreshKind::everything())
                .with_processes(sysinfo::ProcessRefreshKind::everything()),
        )))
    }
}

#[tauri::command]
pub fn get_telemetry(state: tauri::State<'_, TelemetryState>) -> SystemTelemetry {
    let mut sys = state.0.lock().unwrap();
    sys.refresh_cpu_specifics(CpuRefreshKind::everything());
    sys.refresh_memory();
    sys.refresh_processes(ProcessesToUpdate::All, true);

    let cpus = sys.cpus();
    let cpu_usage = if cpus.is_empty() {
        0.0
    } else {
        cpus.iter().map(|c| c.cpu_usage()).sum::<f32>() / cpus.len() as f32
    };

    let total_memory = sys.total_memory() as f32;
    let used_memory = sys.used_memory() as f32;
    let ram_usage = if total_memory > 0.0 {
        (used_memory / total_memory) * 100.0
    } else {
        0.0
    };

    let mut disk_io: f32 = 0.0;
    for (_, p) in sys.processes() {
        let disk = p.disk_usage();
        disk_io += (disk.written_bytes + disk.read_bytes) as f32 / (1024.0 * 1024.0);
    }
    disk_io = disk_io.min(100.0);

    let process_count = sys.processes().len();

    SystemTelemetry {
        cpu_usage,
        ram_usage,
        disk_io,
        network_io: 0.0,
        active_processes: process_count,
    }
}
