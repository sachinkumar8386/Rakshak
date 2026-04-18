use std::collections::HashSet;
use std::sync::{Arc, RwLock};

#[cfg(windows)]
use std::process::Command;

pub struct ShadowCopyMonitor {
    protected: Arc<RwLock<bool>>,
    deletion_events: Arc<RwLock<Vec<VssEvent>>>,
    last_snapshot_time: Arc<RwLock<std::time::Instant>>,
}

#[derive(Clone, Debug)]
pub struct VssEvent {
    pub timestamp: std::time::Instant,
    pub event_type: VssEventType,
    pub source_process: String,
    pub pid: u32,
}

#[derive(Clone, Debug, PartialEq)]
pub enum VssEventType {
    SnapshotCreated,
    SnapshotDeleted,
    SnapshotListed,
    DeletionAttempted,
}

impl ShadowCopyMonitor {
    pub fn new() -> Self {
        Self {
            protected: Arc::new(RwLock::new(false)),
            deletion_events: Arc::new(RwLock::new(Vec::new())),
            last_snapshot_time: Arc::new(RwLock::new(std::time::Instant::now())),
        }
    }

    pub fn is_protected(&self) -> bool {
        self.protected.read().map(|p| *p).unwrap_or(false)
    }

    pub fn record_deletion_attempt(&self, pid: u32, process_name: String) {
        log::warn!(
            "[VSSMonitor] Shadow copy deletion attempt detected from {} (PID {})",
            process_name,
            pid
        );

        if let Ok(mut events) = self.deletion_events.write() {
            events.push(VssEvent {
                timestamp: std::time::Instant::now(),
                event_type: VssEventType::DeletionAttempted,
                source_process: process_name,
                pid,
            });

            if events.len() > 100 {
                events.remove(0);
            }
        }
    }

    pub fn create_protective_snapshot(&self) -> Result<(), String> {
        log::info!("[VSSMonitor] Creating protective shadow copy...");

        #[cfg(windows)]
        {
            let output = Command::new("powershell")
                .args(["-Command", "vssadmin create shadow /for=C: /quiet"])
                .output();

            match output {
                Ok(result) => {
                    if result.status.success() {
                        *self.last_snapshot_time.write().unwrap() = std::time::Instant::now();
                        log::info!("[VSSMonitor] Protective snapshot created successfully");
                        return Ok(());
                    } else {
                        let err = String::from_utf8_lossy(&result.stderr);
                        log::warn!("[VSSMonitor] Snapshot creation failed: {}", err);
                        return Err(format!("Failed to create snapshot: {}", err));
                    }
                }
                Err(e) => {
                    return Err(format!("Failed to execute vssadmin: {}", e));
                }
            }
        }

        #[cfg(not(windows))]
        {
            Err("Shadow copies not supported on this platform".to_string())
        }
    }

    pub fn get_recent_deletions(&self) -> Vec<VssEvent> {
        self.deletion_events
            .read()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    pub fn should_create_snapshot(&self, interval_secs: u64) -> bool {
        let last = *self.last_snapshot_time.read().unwrap();
        let elapsed = std::time::Instant::now().duration_since(last);
        elapsed.as_secs() >= interval_secs
    }

    pub fn get_deletion_count(&self, within_secs: u64) -> usize {
        let cutoff = std::time::Instant::now() - std::time::Duration::from_secs(within_secs);

        self.deletion_events
            .read()
            .map(|events| events.iter().filter(|e| e.timestamp >= cutoff).count())
            .unwrap_or(0)
    }
}

impl Default for ShadowCopyMonitor {
    fn default() -> Self {
        Self::new()
    }
}
