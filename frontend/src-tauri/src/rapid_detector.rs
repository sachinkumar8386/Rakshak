use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::{Deserialize, Serialize};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, RefreshKind, System};

#[cfg(windows)]
use windows::Win32::System::Threading::{
    OpenProcess, TerminateProcess, PROCESS_QUERY_INFORMATION, PROCESS_TERMINATE,
};

pub const BULK_THRESHOLD: usize = 10;
pub const EARLY_KILL_FILES: usize = 3;
pub const MIN_READ_WRITE_MIX: usize = 2;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub level: String,
    pub pid: u32,
    pub process: String,
    pub file: String,
    pub action: String,
    pub read_count: usize,
    pub write_count: usize,
    pub velocity: f64,
    pub timestamp: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProcessScore {
    pub pid: u32,
    pub name: String,
    pub score: u32,
    pub event_count: usize,
    pub read_count: usize,
    pub write_count: usize,
    pub is_ransomware: bool,
    pub is_suspicious: bool,
}

struct ProcessEntry {
    pid: u32,
    name: String,
    read_files: HashSet<PathBuf>,
    write_files: HashSet<PathBuf>,
    all_files: Vec<PathBuf>,
    first_seen: Instant,
    last_seen: Instant,
    score: u32,
    reported: bool,
}

pub struct RapidDetector {
    processes: HashMap<u32, ProcessEntry>,
    killed_pids: HashSet<u32>,
    sys: System,
}

impl RapidDetector {
    pub fn new() -> Self {
        Self {
            processes: HashMap::new(),
            killed_pids: HashSet::new(),
            sys: System::new_with_specifics(
                RefreshKind::nothing().with_processes(ProcessRefreshKind::everything()),
            ),
        }
    }

    fn get_process_name(&mut self, pid: u32) -> String {
        self.sys.refresh_processes(ProcessesToUpdate::All, true);
        self.sys
            .process(Pid::from_u32(pid))
            .map(|p| p.name().to_string_lossy().to_string())
            .unwrap_or_else(|| format!("PID:{}", pid))
    }

    pub fn record_read(&mut self, pid: u32, path: &PathBuf) -> Option<ThreatAlert> {
        self.record_event(pid, path, true)
    }

    pub fn record_write(&mut self, pid: u32, path: &PathBuf) -> Option<ThreatAlert> {
        self.record_event(pid, path, false)
    }

    fn record_event(&mut self, pid: u32, path: &PathBuf, is_read: bool) -> Option<ThreatAlert> {
        if self.killed_pids.contains(&pid) || pid <= 4 {
            return None;
        }

        let now = Instant::now();
        let name = self.get_process_name(pid);

        let entry = self.processes.entry(pid).or_insert_with(|| ProcessEntry {
            pid,
            name: name.clone(),
            read_files: HashSet::new(),
            write_files: HashSet::new(),
            all_files: Vec::new(),
            first_seen: now,
            last_seen: now,
            score: 0,
            reported: false,
        });

        entry.last_seen = now;
        if entry.name.is_empty() || entry.name.starts_with("PID:") {
            entry.name = name.clone();
        }

        if is_read {
            entry.read_files.insert(path.clone());
        } else {
            entry.write_files.insert(path.clone());
        }

        if !entry.all_files.contains(path) {
            entry.all_files.push(path.clone());
        }

        let total_events = entry.read_files.len() + entry.write_files.len();
        let elapsed_ms = now.duration_since(entry.first_seen).as_millis() as f64;
        let velocity = if elapsed_ms > 0.0 {
            (total_events as f64 / elapsed_ms) * 1000.0
        } else {
            0.0
        };

        let read_write_mix = entry.read_files.len().min(entry.write_files.len());

        if total_events >= EARLY_KILL_FILES && read_write_mix >= MIN_READ_WRITE_MIX {
            entry.score = 100;
            entry.reported = true;
            self.killed_pids.insert(pid);

            kill_process(pid);
            self.sys.refresh_processes(ProcessesToUpdate::All, true);
            let final_name = self
                .sys
                .process(Pid::from_u32(pid))
                .map(|p| p.name().to_string_lossy().to_string())
                .unwrap_or_else(|| entry.name.clone());

            log::error!(
                "[RAKSHAK] KILLED after {} files | Read:{} Write:{} | {} (PID {})",
                total_events,
                entry.read_files.len(),
                entry.write_files.len(),
                final_name,
                pid
            );

            return Some(ThreatAlert {
                level: "CRITICAL".to_string(),
                pid,
                process: final_name,
                file: path.to_string_lossy().to_string(),
                action: "KILLED_EARLY".to_string(),
                read_count: entry.read_files.len(),
                write_count: entry.write_files.len(),
                velocity,
                timestamp: timestamp_now(),
            });
        }

        if total_events >= BULK_THRESHOLD && read_write_mix >= MIN_READ_WRITE_MIX {
            entry.score = 100;
            entry.reported = true;
            self.killed_pids.insert(pid);
            kill_process(pid);

            log::error!(
                "[RAKSHAK] BULK KILL | {} files | Read:{} Write:{} | {} (PID {})",
                total_events,
                entry.read_files.len(),
                entry.write_files.len(),
                entry.name,
                pid
            );

            return Some(ThreatAlert {
                level: "CRITICAL".to_string(),
                pid,
                process: entry.name.clone(),
                file: path.to_string_lossy().to_string(),
                action: "KILLED_BULK".to_string(),
                read_count: entry.read_files.len(),
                write_count: entry.write_files.len(),
                velocity,
                timestamp: timestamp_now(),
            });
        }

        if total_events >= 5 && read_write_mix >= 1 {
            entry.score = 60;
            if !entry.reported {
                entry.reported = true;
                return Some(ThreatAlert {
                    level: "HIGH".to_string(),
                    pid,
                    process: entry.name.clone(),
                    file: path.to_string_lossy().to_string(),
                    action: "SUSPICIOUS".to_string(),
                    read_count: entry.read_files.len(),
                    write_count: entry.write_files.len(),
                    velocity,
                    timestamp: timestamp_now(),
                });
            }
        }

        None
    }

    pub fn cleanup_stale(&mut self) {
        let now = Instant::now();
        self.processes.retain(|_, entry| {
            now.duration_since(entry.last_seen) < std::time::Duration::from_secs(30)
        });
    }

    pub fn get_scores(&self) -> Vec<ProcessScore> {
        self.processes
            .values()
            .map(|e| ProcessScore {
                pid: e.pid,
                name: e.name.clone(),
                score: e.score,
                event_count: e.read_files.len() + e.write_files.len(),
                read_count: e.read_files.len(),
                write_count: e.write_files.len(),
                is_ransomware: e.score >= 100,
                is_suspicious: e.score >= 60,
            })
            .collect()
    }

    pub fn killed_pids_mut(&mut self) -> &mut HashSet<u32> {
        &mut self.killed_pids
    }

    pub fn processes_mut(&mut self) -> &mut HashMap<u32, ProcessEntry> {
        &mut self.processes
    }
}

fn kill_process(pid: u32) {
    #[cfg(windows)]
    {
        unsafe {
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_TERMINATE, false, pid);
            if handle.is_ok() {
                let _ = TerminateProcess(handle.unwrap(), 1);
                log::info!("[RAKSHAK] Process {} terminated", pid);
            }
        }
    }
    #[cfg(not(windows))]
    {
        let _ = pid;
    }
}

fn timestamp_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:?}", now)
}
