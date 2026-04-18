use walkdir::WalkDir;
use serde::Serialize;
use crate::entropy::{file_entropy, ENTROPY_THRESHOLD};

#[derive(Serialize)]
pub struct ScanResultItem {
    pub path: String,
    pub entropy: f64,
    pub is_suspicious: bool,
}

#[tauri::command]
pub async fn scan_directory(path: String) -> Result<Vec<ScanResultItem>, String> {
    let mut results = Vec::new();
    
    // Process up to 1000 files to avoid total lock on entire drives
    let mut count = 0;
    for entry in WalkDir::new(&path).into_iter().filter_map(|e| e.ok()) {
        if count > 1000 { break; }
        if entry.file_type().is_file() {
            if let Some(ent) = file_entropy(entry.path(), 65536) {
                if ent > ENTROPY_THRESHOLD - 1.0 { // show slightly suspicious ones too for demo
                    results.push(ScanResultItem {
                        path: entry.path().to_string_lossy().to_string(),
                        entropy: ent,
                        is_suspicious: ent > ENTROPY_THRESHOLD,
                    });
                }
            }
            count += 1;
        }
    }
    
    results.sort_by(|a, b| b.entropy.partial_cmp(&a.entropy).unwrap_or(std::cmp::Ordering::Equal));
    Ok(results)
}
