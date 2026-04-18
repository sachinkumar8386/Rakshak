/// Multi-Signal Ransomware Detection Engine
///
/// Implements a scoring-based detection system with 7 vectors:
/// 1. File modification rate (per-process)
/// 2. High entropy detection
/// 3. Extension change detection
/// 4. Sequential bulk modification pattern
/// 5. Honeypot trigger (immediate)
/// 6. Multi-signal correlation scoring
/// 7. Sliding window analysis (global)
use std::collections::{HashMap, HashSet, VecDeque};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::Serialize;

// ─── Configuration Constants ────────────────────────────────────────────────

/// Score awarded for each signal type
const SCORE_HIGH_MOD_RATE: u32 = 10;
const SCORE_HIGH_ENTROPY: u32 = 30;
const SCORE_EXTENSION_CHANGE: u32 = 35; // First-strike capable
const SCORE_SEQUENTIAL_PATTERN: u32 = 10;
const SCORE_HONEYPOT_TRIGGER: u32 = 100;
/// Detection thresholds
const THRESHOLD_RANSOMWARE: u32 = 80;
const THRESHOLD_SUSPICIOUS: u32 = 15;
const THRESHOLD_FIRST_STRIKE: u32 = 35;

/// Rate-based detection: max files a process may modify within the time window
const RATE_LIMIT_FILES: usize = 3;
const RATE_LIMIT_WINDOW_SECS: u64 = 5;

/// Sequential pattern: bulk files modified in order
const SEQUENTIAL_BULK_COUNT: usize = 5;
const SEQUENTIAL_WINDOW_SECS: u64 = 15;

/// Sliding window: global event analysis
const SLIDING_WINDOW_SIZE: usize = 50;
/// If this fraction of recent events are suspicious, trigger global alert
const SLIDING_WINDOW_THRESHOLD: f64 = 0.6;

/// Max events stored per process tracker
const MAX_EVENTS_PER_PROCESS: usize = 100;

/// Max global events
const MAX_GLOBAL_EVENTS: usize = 200;

/// Entropy threshold (re-exported from crate::entropy for convenience)
const ENTROPY_THRESHOLD: f64 = 7.5;

/// Velocity thresholds (files per second)
const VELOCITY_SAFE: usize = 3;
const VELOCITY_SUSPICIOUS: usize = 5;
const VELOCITY_CRITICAL: usize = 10;

/// Decision matrix thresholds
const ENTROPY_SUSPICIOUS: f64 = 6.0;
const ENTROPY_CRITICAL: f64 = 6.5;

/// Bulk detection threshold - kill immediately if this many files modified in quick succession
const BULK_DETECTION_THRESHOLD: usize = 10;

// ─── Data Structures ────────────────────────────────────────────────────────

/// A single filesystem event enriched with detection metadata.
#[derive(Clone, Debug)]
pub struct FileEvent {
    pub timestamp: Instant,
    pub path: PathBuf,
    pub original_extension: Option<String>,
    pub current_extension: Option<String>,
    pub entropy: f64,
    pub pid: u32,
    pub process_name: String,
    pub is_honeypot: bool,
    /// Whether this individual event is suspicious
    pub suspicious: bool,
}

/// Per-process tracking state.
#[derive(Debug)]
struct ProcessTracker {
    pub pid: u32,
    pub name: String,
    pub score: u32,
    pub events: VecDeque<FileEvent>,
    pub last_seen: Instant,
    /// Whether this process has already been reported as ransomware
    pub reported_ransomware: bool,
    /// Whether this process has already been reported as suspicious
    pub reported_suspicious: bool,
}

impl ProcessTracker {
    fn new(pid: u32, name: String, now: Instant) -> Self {
        Self {
            pid,
            name,
            score: 0,
            events: VecDeque::with_capacity(MAX_EVENTS_PER_PROCESS),
            last_seen: now,
            reported_ransomware: false,
            reported_suspicious: false,
        }
    }

    fn push_event(&mut self, event: FileEvent) {
        self.last_seen = event.timestamp;
        if self.events.len() >= MAX_EVENTS_PER_PROCESS {
            self.events.pop_front();
        }
        self.events.push_back(event);
    }

    /// Count events within the last N seconds
    fn events_in_window(&self, window_secs: u64) -> usize {
        let cutoff = self
            .last_seen
            .checked_sub(std::time::Duration::from_secs(window_secs));
        match cutoff {
            Some(cutoff) => self.events.iter().filter(|e| e.timestamp >= cutoff).count(),
            None => self.events.len(),
        }
    }
}

/// Result returned after processing a file event.
#[derive(Clone, Debug, Serialize)]
pub enum DetectionVerdict {
    /// No threat detected
    Clean,
    /// Suspicious activity (score >= 5)
    Suspicious {
        pid: u32,
        process_name: String,
        score: u32,
        reasons: Vec<String>,
    },
    /// Ransomware detected (score >= 8)
    Ransomware {
        pid: u32,
        process_name: String,
        score: u32,
        reasons: Vec<String>,
    },
}

/// Per-process score summary for the frontend.
#[derive(Clone, Debug, Serialize)]
pub struct ProcessScore {
    pub pid: u32,
    pub name: String,
    pub score: u32,
    pub event_count: usize,
    pub is_ransomware: bool,
    pub is_suspicious: bool,
}

// ─── Detection Engine ───────────────────────────────────────────────────────

pub struct DetectionEngine {
    /// Per-process trackers keyed by PID
    trackers: HashMap<u32, ProcessTracker>,
    /// Global sliding window of recent events
    global_events: VecDeque<FileEvent>,
    /// Set of honeypot file paths (absolute, lowercase for case-insensitive match)
    honeypot_paths: HashSet<PathBuf>,
}

impl DetectionEngine {
    pub fn new() -> Self {
        Self {
            trackers: HashMap::new(),
            global_events: VecDeque::with_capacity(MAX_GLOBAL_EVENTS),
            honeypot_paths: HashSet::new(),
        }
    }

    /// Register a honeypot file path so any access triggers immediate alert.
    pub fn register_honeypot(&mut self, path: PathBuf) {
        // Normalize to lowercase for case-insensitive matching on Windows
        let normalized = PathBuf::from(path.to_string_lossy().to_lowercase());
        log::info!("[Detection] Honeypot registered: {}", normalized.display());
        self.honeypot_paths.insert(normalized);
    }

    /// Check if a path is a registered honeypot.
    pub fn is_honeypot(&self, path: &Path) -> bool {
        let normalized = PathBuf::from(path.to_string_lossy().to_lowercase());
        self.honeypot_paths.contains(&normalized)
    }

    /// Process a new file event and return a detection verdict.
    pub fn process_event(&mut self, mut event: FileEvent) -> DetectionVerdict {
        let now = event.timestamp;
        let pid = event.pid;

        // ── Check honeypot ──────────────────────────────────────────────
        event.is_honeypot = self.is_honeypot(&event.path);

        // ── Get or create tracker ───────────────────────────────────────
        let tracker = self
            .trackers
            .entry(pid)
            .or_insert_with(|| ProcessTracker::new(pid, event.process_name.clone(), now));

        // ── Compute per-signal scores ───────────────────────────────────
        let mut delta_score: u32 = 0;
        let mut reasons: Vec<String> = Vec::new();

        // Signal 1: Honeypot trigger (+5, IMMEDIATE)
        if event.is_honeypot {
            // Rapid kill: honeypot is an immediate 100
            reasons.push(format!(
                "HONEYPOT TRIGGER: {} accessed decoy file {}",
                event.process_name,
                event.path.display()
            ));
            log::warn!(
                "[Detection] HONEYPOT TRIGGER by PID {} ({}) on {}",
                pid,
                event.process_name,
                event.path.display()
            );
            // First-strike: honeypot is an immediate kill
            return DetectionVerdict::Ransomware {
                pid,
                process_name: event.process_name,
                score: SCORE_HONEYPOT_TRIGGER,
                reasons: vec![format!("HONEYPOT TRIGGER on {}", event.path.display())],
            };
        }

        // Signal 2: High entropy (+3)
        if event.entropy > ENTROPY_THRESHOLD {
            delta_score += SCORE_HIGH_ENTROPY;
            reasons.push(format!(
                "HIGH ENTROPY: {:.2} bits/byte on {}",
                event.entropy,
                event.path.file_name().unwrap_or_default().to_string_lossy()
            ));
        }

        // Signal 3: Extension change (+2)
        let ext_changed = has_suspicious_extension_change(
            event.original_extension.as_deref(),
            event.current_extension.as_deref(),
        );
        if ext_changed {
            delta_score += SCORE_EXTENSION_CHANGE;
            reasons.push(format!(
                "EXTENSION CHANGE: {} → {} on {}",
                event.original_extension.as_deref().unwrap_or("(none)"),
                event.current_extension.as_deref().unwrap_or("(none)"),
                event.path.file_name().unwrap_or_default().to_string_lossy()
            ));
        }

        if delta_score > 0 {
            log::debug!(
                "[Detection] PID {} ({}) Delta: +{}, Total: {}, Reasons: {:?}",
                pid,
                event.process_name,
                delta_score,
                tracker.score + delta_score,
                reasons
            );
        }

        // Mark event as suspicious if it has any signal
        event.suspicious = delta_score > 0;

        // Record event in tracker
        tracker.push_event(event.clone());

        // Signal 4: High file modification rate (+3)
        let recent_count = tracker.events_in_window(RATE_LIMIT_WINDOW_SECS);
        if recent_count > RATE_LIMIT_FILES {
            // Only award once per crossing
            if recent_count == RATE_LIMIT_FILES + 1
                || (recent_count > RATE_LIMIT_FILES && tracker.score < SCORE_HIGH_MOD_RATE)
            {
                delta_score += SCORE_HIGH_MOD_RATE;
                reasons.push(format!(
                    "HIGH MOD RATE: {} files modified in {}s by {}",
                    recent_count, RATE_LIMIT_WINDOW_SECS, tracker.name
                ));
            }
        }

        // Signal 5: Sequential bulk pattern (+2)
        if tracker.events.len() >= SEQUENTIAL_BULK_COUNT {
            let window_events: Vec<&FileEvent> = tracker
                .events
                .iter()
                .filter(|e| now.duration_since(e.timestamp).as_secs() < SEQUENTIAL_WINDOW_SECS)
                .collect();

            if window_events.len() >= SEQUENTIAL_BULK_COUNT {
                // Check if events are "sequential" — files in the same directory
                // or extensions being modified in order
                let dirs: HashSet<&Path> = window_events
                    .iter()
                    .filter_map(|e| e.path.parent())
                    .collect();
                // If most events target the same 1-2 directories, it's sequential
                if dirs.len() <= 2 {
                    delta_score += SCORE_SEQUENTIAL_PATTERN;
                    reasons.push(format!(
                        "SEQUENTIAL PATTERN: {} files modified in {} dirs within {}s",
                        window_events.len(),
                        dirs.len(),
                        SEQUENTIAL_WINDOW_SECS
                    ));
                }
            }
        }

        // ── Update tracker score ────────────────────────────────────────
        tracker.score = tracker.score.saturating_add(delta_score);
        let current_score = tracker.score;
        let process_name = tracker.name.clone();

        // ── First-Strike Rule ───────────────────────────────────────────
        if delta_score >= THRESHOLD_FIRST_STRIKE {
            tracker.reported_ransomware = true;
            return DetectionVerdict::Ransomware {
                pid,
                process_name,
                score: delta_score,
                reasons: reasons.clone(),
            };
        }

        // ── Push to global sliding window ───────────────────────────────
        if self.global_events.len() >= MAX_GLOBAL_EVENTS {
            self.global_events.pop_front();
        }
        self.global_events.push_back(event);

        // ── Signal 7: Sliding window global analysis ────────────────────
        // Check if a large fraction of recent global events are suspicious
        if self.global_events.len() >= SLIDING_WINDOW_SIZE {
            let recent: Vec<&FileEvent> = self
                .global_events
                .iter()
                .rev()
                .take(SLIDING_WINDOW_SIZE)
                .collect();
            let suspicious_count = recent.iter().filter(|e| e.suspicious).count();
            let suspicious_ratio = suspicious_count as f64 / recent.len() as f64;

            if suspicious_ratio >= SLIDING_WINDOW_THRESHOLD {
                // Boost the current tracker over the threshold
                let tracker = self.trackers.get_mut(&pid).unwrap();
                if tracker.score < THRESHOLD_RANSOMWARE {
                    let boost = THRESHOLD_RANSOMWARE - tracker.score;
                    tracker.score += boost;
                    log::warn!(
                        "[Detection] SLIDING WINDOW: {:.0}% of last {} events suspicious — boosted PID {} score by {}",
                        suspicious_ratio * 100.0, SLIDING_WINDOW_SIZE, pid, boost
                    );
                    return DetectionVerdict::Ransomware {
                        pid,
                        process_name,
                        score: tracker.score,
                        reasons: vec![format!(
                            "SLIDING WINDOW: {:.0}% of last {} global events are suspicious",
                            suspicious_ratio * 100.0,
                            SLIDING_WINDOW_SIZE
                        )],
                    };
                }
            }
        }

        // ── Emit verdict ────────────────────────────────────────────────
        let tracker = self.trackers.get_mut(&pid).unwrap();

        if current_score >= THRESHOLD_RANSOMWARE {
            tracker.reported_ransomware = true;
            log::error!(
                "[Detection] RANSOMWARE DETECTED: PID {} ({}) score={} reasons={:?}",
                pid,
                process_name,
                current_score,
                reasons
            );
            DetectionVerdict::Ransomware {
                pid,
                process_name,
                score: current_score,
                reasons,
            }
        } else if current_score >= THRESHOLD_SUSPICIOUS && !tracker.reported_suspicious {
            tracker.reported_suspicious = true;
            log::warn!(
                "[Detection] SUSPICIOUS: PID {} ({}) score={} reasons={:?}",
                pid,
                process_name,
                current_score,
                reasons
            );
            DetectionVerdict::Suspicious {
                pid,
                process_name,
                score: current_score,
                reasons,
            }
        } else if delta_score > 0 && !reasons.is_empty() && current_score >= THRESHOLD_SUSPICIOUS {
            // Re-emit suspicious if new signals appeared this event
            DetectionVerdict::Suspicious {
                pid,
                process_name,
                score: current_score,
                reasons,
            }
        } else {
            DetectionVerdict::Clean
        }
    }

    /// Get all process scores for the frontend.
    pub fn get_scores(&self) -> Vec<ProcessScore> {
        self.trackers
            .values()
            .map(|t| ProcessScore {
                pid: t.pid,
                name: t.name.clone(),
                score: t.score,
                event_count: t.events.len(),
                is_ransomware: t.score >= THRESHOLD_RANSOMWARE,
                is_suspicious: t.score >= THRESHOLD_SUSPICIOUS,
            })
            .collect()
    }

    /// Get all honeypot paths
    pub fn get_honeypot_paths(&self) -> Vec<PathBuf> {
        self.honeypot_paths.iter().cloned().collect()
    }
}

// ─── Extension Analysis Helpers ─────────────────────────────────────────────

/// Known ransomware file extensions
const SUSPICIOUS_EXTENSIONS: &[&str] = &[
    "encrypted",
    "locked",
    "crypt",
    "enc",
    "locky",
    "cerber",
    "zepto",
    "zzzzz",
    "micro",
    "crypted",
    "cry",
    "crypto",
    "lockbit",
    "dharma",
    "phobos",
    "ryuk",
    "maze",
    "sodinokibi",
    "revil",
    "conti",
    "hive",
    "aes",
    "rsa",
    "pays",
    "ransom",
    "wasted",
    "xxx",
    "bleep",
];

/// Checks if an extension change is suspicious.
/// Returns true if:
/// - The new extension is in the suspicious list
/// - The original extension was a normal document type and changed
fn has_suspicious_extension_change(original: Option<&str>, current: Option<&str>) -> bool {
    let current = match current {
        Some(ext) => ext.to_lowercase(),
        None => return false,
    };

    // Direct match against known ransomware extensions
    if SUSPICIOUS_EXTENSIONS.iter().any(|&s| current == s) {
        return true;
    }

    // If original had a normal extension and it changed to something very different
    if let Some(orig) = original {
        let orig = orig.to_lowercase();
        if orig != current && is_normal_document_ext(&orig) && !is_normal_document_ext(&current) {
            // Extension was changed from a normal type to an unknown type
            return true;
        }
    }

    false
}

/// Normal document/media extensions that shouldn't change unexpectedly.
fn is_normal_document_ext(ext: &str) -> bool {
    matches!(
        ext,
        "txt"
            | "doc"
            | "docx"
            | "xls"
            | "xlsx"
            | "ppt"
            | "pptx"
            | "pdf"
            | "jpg"
            | "jpeg"
            | "png"
            | "gif"
            | "bmp"
            | "mp3"
            | "mp4"
            | "avi"
            | "mkv"
            | "zip"
            | "rar"
            | "7z"
            | "csv"
            | "html"
            | "xml"
            | "json"
            | "py"
            | "rs"
            | "js"
            | "ts"
            | "cpp"
            | "c"
            | "h"
            | "java"
            | "sql"
            | "db"
            | "sqlite"
            | "md"
            | "toml"
            | "yaml"
            | "yml"
            | "ini"
            | "cfg"
            | "log"
            | "rtf"
            | "odt"
            | "ods"
            | "odp"
            | "svg"
            | "webp"
            | "ico"
    )
}

// ─── Honeypot File Management ───────────────────────────────────────────────

/// Decoy file definitions: (name, content)
const HONEYPOT_FILES: &[(&str, &str)] = &[
    ("_passwords.txt", "Gmail: admin@gmail.com / p@ssw0rd123\nBank: 4532-XXXX-XXXX-1234\n"),
    ("_recovery_key.docx.txt", "BitLocker Recovery Key: 123456-789012-345678-901234-567890-123456-789012-345678\n"),
    ("_bank_statement.csv", "Date,Description,Amount\n2026-01-15,Salary,5000.00\n2026-01-20,Transfer,-2000.00\n"),
    ("_tax_returns_2025.txt", "SSN: 123-45-6789\nFiling Status: Single\nAGI: $85,000\n"),
    ("aaa_wallet_seed_phrase.txt", "1. ocean 2. blast 3. mountain 4. logic 5. planet 6. digital 7. shadow 8. silver 9. winter 10. sudden 11. nature 12. light\n"),
];

/// Create honeypot files in the given directories and return their paths.
pub fn deploy_honeypots(dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut paths = Vec::new();

    for dir in dirs {
        if !dir.exists() {
            continue;
        }
        for &(name, content) in HONEYPOT_FILES {
            let path = dir.join(name);
            if path.exists() {
                // Already deployed, just register
                paths.push(path);
                continue;
            }
            match std::fs::write(&path, content) {
                Ok(_) => {
                    log::info!("[Honeypot] Deployed: {}", path.display());

                    // Set Hidden + System attributes on Windows
                    #[cfg(windows)]
                    {
                        use std::os::windows::ffi::OsStrExt;
                        let wide: Vec<u16> =
                            path.as_os_str().encode_wide().chain(Some(0)).collect();
                        unsafe {
                            let _ = windows::Win32::Storage::FileSystem::SetFileAttributesW(
                                windows::core::PCWSTR(wide.as_ptr()),
                                windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_HIDDEN
                                    | windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_SYSTEM,
                            );
                        }
                    }

                    paths.push(path);
                }
                Err(e) => {
                    log::warn!("[Honeypot] Failed to deploy {}: {e}", path.display());
                }
            }
        }
    }

    paths
}

// ─── Decision Matrix ────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResponseAction {
    Allow,
    Monitor,
    Alert,
    Suspend,
    KillAndIsolate,
}

impl ResponseAction {
    pub fn from_decision_matrix(
        entropy: f64,
        velocity: usize,
        extension_changed: bool,
        is_honeypot: bool,
    ) -> Self {
        // Honeypot trigger = immediate kill
        if is_honeypot {
            return ResponseAction::KillAndIsolate;
        }

        // BULK DETECTION: If more than 10 files modified quickly, kill immediately
        if velocity >= BULK_DETECTION_THRESHOLD {
            return ResponseAction::KillAndIsolate;
        }

        // Very high entropy alone = kill (encrypted data is ~7.0+ entropy)
        if entropy >= 6.5 {
            return ResponseAction::KillAndIsolate;
        }

        // High entropy + any extension change = kill
        if entropy >= 6.0 && (extension_changed || velocity >= VELOCITY_SUSPICIOUS) {
            return ResponseAction::KillAndIsolate;
        }

        // Medium-high: Suspicious activity
        if entropy >= 5.5 && velocity >= VELOCITY_SUSPICIOUS {
            return ResponseAction::Suspend;
        }

        // Extension change alone = alert
        if extension_changed {
            return ResponseAction::Alert;
        }

        // Low velocity but elevated entropy = monitor
        if entropy >= 4.5 || velocity > VELOCITY_SAFE {
            return ResponseAction::Monitor;
        }

        // Safe
        ResponseAction::Allow
    }

    pub fn speed_ms(&self) -> u64 {
        match self {
            ResponseAction::Allow => 0,
            ResponseAction::Monitor => 5000,
            ResponseAction::Alert => 1000,
            ResponseAction::Suspend => 100,
            ResponseAction::KillAndIsolate => 50,
        }
    }

    pub fn description(&self) -> &'static str {
        match self {
            ResponseAction::Allow => "Process allowed",
            ResponseAction::Monitor => "Continue monitoring",
            ResponseAction::Alert => "Alert user and increase monitoring",
            ResponseAction::Suspend => "Suspend process pending review",
            ResponseAction::KillAndIsolate => "Kill process and isolate immediately",
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suspicious_extension() {
        assert!(has_suspicious_extension_change(
            Some("txt"),
            Some("encrypted")
        ));
        assert!(has_suspicious_extension_change(
            Some("docx"),
            Some("locked")
        ));
        assert!(has_suspicious_extension_change(None, Some("locky")));
        // Normal rename should not trigger
        assert!(!has_suspicious_extension_change(Some("txt"), Some("md")));
        // Same extension
        assert!(!has_suspicious_extension_change(Some("txt"), Some("txt")));
    }

    #[test]
    fn test_normal_ext_to_unknown() {
        // Normal doc ext changed to something weird
        assert!(has_suspicious_extension_change(Some("pdf"), Some("xq7z")));
    }

    #[test]
    fn test_honeypot_detection() {
        let mut engine = DetectionEngine::new();
        let honey = PathBuf::from("C:\\Users\\test\\Documents\\_passwords.txt");
        engine.register_honeypot(honey.clone());
        assert!(engine.is_honeypot(&honey));
        assert!(!engine.is_honeypot(Path::new("C:\\other\\file.txt")));
    }

    #[test]
    fn test_scoring_entropy_plus_extension() {
        let mut engine = DetectionEngine::new();

        // A single event with high entropy + extension change = score 5 (SUSPICIOUS)
        let event = FileEvent {
            timestamp: Instant::now(),
            path: PathBuf::from("C:\\Users\\test\\doc.encrypted"),
            original_extension: Some("txt".into()),
            current_extension: Some("encrypted".into()),
            entropy: 7.9,
            pid: 1234,
            process_name: "evil.exe".into(),
            is_honeypot: false,
            suspicious: false,
        };

        let verdict = engine.process_event(event);
        match verdict {
            DetectionVerdict::Ransomware { score, .. } => {
                assert!(
                    score >= THRESHOLD_RANSOMWARE,
                    "Expected score >= {}, got {}",
                    THRESHOLD_RANSOMWARE,
                    score
                );
            }
            DetectionVerdict::Suspicious { score, .. } => {
                assert!(
                    score >= THRESHOLD_SUSPICIOUS,
                    "Expected score >= {}, got {}",
                    THRESHOLD_SUSPICIOUS,
                    score
                );
            }
            DetectionVerdict::Clean => panic!("Expected detection, got clean"),
        }
    }

    #[test]
    fn test_honeypot_immediate_detection() {
        let mut engine = DetectionEngine::new();
        let honey = PathBuf::from("c:\\users\\test\\documents\\_passwords.txt");
        engine.register_honeypot(honey.clone());

        let event = FileEvent {
            timestamp: Instant::now(),
            path: honey,
            original_extension: Some("txt".into()),
            current_extension: Some("txt".into()),
            entropy: 3.0,
            pid: 5678,
            process_name: "ransomware.exe".into(),
            is_honeypot: false,
            suspicious: false,
        };

        let verdict = engine.process_event(event);
        match verdict {
            DetectionVerdict::Suspicious { score, .. }
            | DetectionVerdict::Ransomware { score, .. } => {
                assert!(
                    score >= SCORE_HONEYPOT_TRIGGER,
                    "Honeypot should give at least +5, got {}",
                    score
                );
            }
            DetectionVerdict::Clean => panic!("Expected detection from honeypot, got clean"),
        }
    }
}
