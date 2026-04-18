use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub struct VelocityEvent {
    pub timestamp: Instant,
    pub pid: u32,
    pub file_path: String,
}

pub struct VelocityTracker {
    events: VecDeque<VelocityEvent>,
    pid_velocity: HashMap<u32, usize>,
    window_secs: u64,
    max_events: usize,
}

impl VelocityTracker {
    pub fn new(window_secs: u64, max_events: usize) -> Self {
        Self {
            events: VecDeque::with_capacity(max_events * 10),
            pid_velocity: HashMap::new(),
            window_secs,
            max_events,
        }
    }

    pub fn record(&mut self, pid: u32, file_path: String) {
        let now = Instant::now();
        let cutoff = now - Duration::from_secs(self.window_secs);

        while let Some(oldest) = self.events.front() {
            if oldest.timestamp < cutoff {
                self.events.pop_front();
            } else {
                break;
            }
        }

        self.events.push_back(VelocityEvent {
            timestamp: now,
            pid,
            file_path,
        });

        self.pid_velocity.retain(|_, _| false);

        for event in &self.events {
            *self.pid_velocity.entry(event.pid).or_insert(0) += 1;
        }
    }

    pub fn get_velocity(&self, pid: u32) -> usize {
        self.pid_velocity.get(&pid).copied().unwrap_or(0)
    }

    pub fn check_threshold(&self, pid: u32, threshold: usize) -> bool {
        self.get_velocity(pid) >= threshold
    }
}

pub struct SlidingWindowAnalyzer {
    window_events: VecDeque<(Instant, bool)>,
    capacity: usize,
    suspicious_threshold: f64,
}

impl SlidingWindowAnalyzer {
    pub fn new(capacity: usize, suspicious_threshold: f64) -> Self {
        Self {
            window_events: VecDeque::with_capacity(capacity),
            capacity,
            suspicious_threshold,
        }
    }

    pub fn record(&mut self, suspicious: bool) {
        if self.window_events.len() >= self.capacity {
            self.window_events.pop_front();
        }
        self.window_events.push_back((Instant::now(), suspicious));
    }

    pub fn get_suspicious_ratio(&self) -> f64 {
        if self.window_events.is_empty() {
            return 0.0;
        }
        let suspicious_count = self.window_events.iter().filter(|(_, s)| *s).count();
        suspicious_count as f64 / self.window_events.len() as f64
    }

    pub fn is_global_anomaly(&self) -> bool {
        self.get_suspicious_ratio() >= self.suspicious_threshold
    }
}
