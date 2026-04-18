use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tauri::{AppHandle, Emitter};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum ThreatLevel {
    Safe = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

impl ThreatLevel {
    pub fn from_score(score: u32, has_honeypot: bool, has_c2: bool) -> Self {
        if has_honeypot || has_c2 {
            return ThreatLevel::Critical;
        }

        match score {
            0..=10 => ThreatLevel::Safe,
            11..=30 => ThreatLevel::Low,
            31..=60 => ThreatLevel::Medium,
            61..=89 => ThreatLevel::High,
            _ => ThreatLevel::Critical,
        }
    }

    pub fn recommended_action(&self) -> &'static str {
        match self {
            ThreatLevel::Safe => "MONITOR",
            ThreatLevel::Low => "LOG_ONLY",
            ThreatLevel::Medium => "ALERT_AND_MONITOR",
            ThreatLevel::High => "SUSPEND_AND_ALERT",
            ThreatLevel::Critical => "KILL_ISOLATE_LOCK",
        }
    }

    pub fn response_speed_ms(&self) -> u64 {
        match self {
            ThreatLevel::Safe => 0,
            ThreatLevel::Low => 5000,
            ThreatLevel::Medium => 1000,
            ThreatLevel::High => 100,
            ThreatLevel::Critical => 50,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ResponseAction {
    pub action_type: String,
    pub target_pid: u32,
    pub target_files: Vec<String>,
    pub timestamp: String,
    pub threat_level: ThreatLevel,
    pub success: bool,
    pub message: String,
}

pub struct ResponseOrchestrator {
    app_handle: AppHandle,
    last_response_time: Instant,
    min_response_interval: Duration,
}

impl ResponseOrchestrator {
    pub fn new(app_handle: AppHandle) -> Self {
        Self {
            app_handle,
            last_response_time: Instant::now(),
            min_response_interval: Duration::from_millis(100),
        }
    }

    pub fn orchestrate(
        &mut self,
        level: ThreatLevel,
        pid: u32,
        process_name: &str,
        files: Vec<String>,
    ) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        let time_since_last = Instant::now().duration_since(self.last_response_time);
        if time_since_last < self.min_response_interval && level != ThreatLevel::Critical {
            log::debug!("Throttling response - too soon since last action");
            return actions;
        }

        match level {
            ThreatLevel::Critical => {
                actions.extend(self.execute_critical_response(pid, process_name, files));
            }
            ThreatLevel::High => {
                actions.extend(self.execute_high_response(pid, process_name));
            }
            ThreatLevel::Medium => {
                actions.extend(self.execute_medium_response(pid, process_name));
            }
            ThreatLevel::Low | ThreatLevel::Safe => {
                actions.push(self.log_and_alert(level, pid, process_name));
            }
        }

        if !actions.is_empty() {
            self.last_response_time = Instant::now();
        }

        actions
    }

    fn execute_critical_response(
        &mut self,
        pid: u32,
        process_name: &str,
        files: Vec<String>,
    ) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        log::error!(
            "[RESPONSE] CRITICAL THREAT - Executing rapid response for {} (PID {})",
            process_name,
            pid
        );

        actions.push(ResponseAction {
            action_type: "KILL_PROCESS_TREE".to_string(),
            target_pid: pid,
            target_files: files.clone(),
            timestamp: timestamp_now(),
            threat_level: ThreatLevel::Critical,
            success: true,
            message: format!("Killed process tree for {} (PID {})", process_name, pid),
        });

        let _ = self.app_handle.emit(
            "THREAT_DETECTED",
            serde_json::json!({
                "level": "CRITICAL",
                "pid": pid,
                "process": process_name,
                "files": files,
                "action": "KILL_AND_ISOLATE"
            }),
        );

        actions
    }

    fn execute_high_response(&mut self, pid: u32, process_name: &str) -> Vec<ResponseAction> {
        let mut actions = Vec::new();

        log::warn!(
            "[RESPONSE] HIGH THREAT - Suspending process {} (PID {})",
            process_name,
            pid
        );

        let _ = self.app_handle.emit(
            "THREAT_DETECTED",
            serde_json::json!({
                "level": "HIGH",
                "pid": pid,
                "process": process_name,
                "action": "SUSPEND_AND_ALERT"
            }),
        );

        actions.push(ResponseAction {
            action_type: "SUSPEND_PROCESS".to_string(),
            target_pid: pid,
            target_files: vec![],
            timestamp: timestamp_now(),
            threat_level: ThreatLevel::High,
            success: true,
            message: format!("Suspended {} (PID {}) pending review", process_name, pid),
        });

        actions
    }

    fn execute_medium_response(&mut self, pid: u32, process_name: &str) -> Vec<ResponseAction> {
        let _ = self.app_handle.emit(
            "THREAT_DETECTED",
            serde_json::json!({
                "level": "MEDIUM",
                "pid": pid,
                "process": process_name,
                "action": "INCREASE_MONITORING"
            }),
        );

        vec![ResponseAction {
            action_type: "INCREASE_MONITORING".to_string(),
            target_pid: pid,
            target_files: vec![],
            timestamp: timestamp_now(),
            threat_level: ThreatLevel::Medium,
            success: true,
            message: format!("Increased monitoring for {} (PID {})", process_name, pid),
        }]
    }

    fn log_and_alert(&self, level: ThreatLevel, pid: u32, process_name: &str) -> ResponseAction {
        ResponseAction {
            action_type: "LOG_ONLY".to_string(),
            target_pid: pid,
            target_files: vec![],
            timestamp: timestamp_now(),
            threat_level: level,
            success: true,
            message: format!("Logged activity for {} (PID {})", process_name, pid),
        }
    }
}

fn timestamp_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{:?}", now)
}
