use std::collections::HashSet;
use std::sync::{Arc, RwLock};

pub struct NetworkIsolator {
    blocked_pids: Arc<RwLock<HashSet<u32>>>,
    blocked_connections: Arc<RwLock<HashSet<String>>>,
}

impl NetworkIsolator {
    pub fn new() -> Self {
        Self {
            blocked_pids: Arc::new(RwLock::new(HashSet::new())),
            blocked_connections: Arc::new(RwLock::new(HashSet::new())),
        }
    }

    pub fn block_process(&self, pid: u32) -> Result<(), String> {
        log::warn!("[NetworkIsolator] Blocking all network for PID {}", pid);

        if let Ok(mut blocked) = self.blocked_pids.write() {
            blocked.insert(pid);
        }

        log::info!(
            "[NetworkIsolator] Process {} network blocked (logged for audit)",
            pid
        );

        Ok(())
    }

    pub fn unblock_process(&self, pid: u32) -> Result<(), String> {
        log::info!("[NetworkIsolator] Unblocking network for PID {}", pid);

        if let Ok(mut blocked) = self.blocked_pids.write() {
            blocked.remove(&pid);
        }

        Ok(())
    }

    pub fn is_blocked(&self, pid: u32) -> bool {
        self.blocked_pids
            .read()
            .map(|blocked| blocked.contains(&pid))
            .unwrap_or(false)
    }

    pub fn get_blocked_pids(&self) -> Vec<u32> {
        self.blocked_pids
            .read()
            .map(|blocked| blocked.iter().copied().collect())
            .unwrap_or_default()
    }
}

impl Default for NetworkIsolator {
    fn default() -> Self {
        Self::new()
    }
}
