use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use tracing::{debug, warn};
use zip::ZipArchive;

use crate::error::{EngineError, Result};
use crate::models::{DetectionReason, MatchSource, ThreatSeverity};

pub const MAX_ARCHIVE_FILE_COUNT: usize = 5000;
pub const MAX_ARCHIVE_UNCOMPRESSED_BYTES: u64 = 500 * 1024 * 1024; // 500 MB
pub const MAX_COMPRESSION_RATIO: f64 = 100.0;
pub const MAX_ENTRY_SCAN_SIZE: usize = 32 * 1024 * 1024; // 32 MB per entry

pub struct ArchiveEntryMatch {
    pub entry_name: String,
    pub reasons: Vec<DetectionReason>,
}

pub fn is_zip_file(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        match ext.to_lowercase().as_str() {
            "zip" | "jar" | "war" | "apk" | "docx" | "xlsx" | "pptx" => true,
            _ => false,
        }
    } else {
        false
    }
}

/// Inspects and extracts archive entries safely with zip-bomb protection.
pub fn scan_zip_archive<F>(
    path: &Path,
    depth: usize,
    max_depth: usize,
    mut inspect_entry: F,
) -> Result<Vec<ArchiveEntryMatch>>
where
    F: FnMut(&str, &[u8]) -> Vec<DetectionReason>,
{
    if depth > max_depth {
        debug!("Reached maximum archive recursion depth ({}) at {:?}", max_depth, path);
        return Ok(Vec::new());
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut zip = ZipArchive::new(reader).map_err(|e| {
        EngineError::Archive(format!("Failed to read ZIP archive {:?}: {}", path, e))
    })?;

    let num_entries = zip.len();
    if num_entries > MAX_ARCHIVE_FILE_COUNT {
        return Ok(vec![ArchiveEntryMatch {
            entry_name: "ArchiveHeader".to_string(),
            reasons: vec![DetectionReason::new(
                MatchSource::ArchiveNested,
                "Zip Bomb / File Limit Exceeded",
                format!("Archive contains {} entries (limit is {})", num_entries, MAX_ARCHIVE_FILE_COUNT),
                ThreatSeverity::High,
                0.75,
            )],
        }]);
    }

    let mut total_uncompressed_bytes = 0u64;
    let mut matches = Vec::new();

    for i in 0..num_entries {
        let mut entry = match zip.by_index(i) {
            Ok(e) => e,
            Err(e) => {
                debug!("Failed to read zip entry #{}: {}", i, e);
                continue;
            }
        };

        if entry.is_dir() {
            continue;
        }

        let entry_name = entry.name().to_string();
        let uncompressed_size = entry.size();
        let compressed_size = entry.compressed_size();

        total_uncompressed_bytes += uncompressed_size;
        if total_uncompressed_bytes > MAX_ARCHIVE_UNCOMPRESSED_BYTES {
            warn!("Archive {:?} exceeded total uncompressed size limit", path);
            matches.push(ArchiveEntryMatch {
                entry_name: "ArchiveQuota".to_string(),
                reasons: vec![DetectionReason::new(
                    MatchSource::ArchiveNested,
                    "Archive Bomb (Excessive Total Size)",
                    format!("Archive extracted size exceeds {} MB limit", MAX_ARCHIVE_UNCOMPRESSED_BYTES / (1024 * 1024)),
                    ThreatSeverity::High,
                    0.75,
                )],
            });
            break;
        }

        // Zip bomb compression ratio check (e.g. 42.zip has huge ratio)
        if compressed_size > 0 {
            let ratio = uncompressed_size as f64 / compressed_size as f64;
            if ratio > MAX_COMPRESSION_RATIO && uncompressed_size > 10 * 1024 * 1024 {
                matches.push(ArchiveEntryMatch {
                    entry_name: entry_name.clone(),
                    reasons: vec![DetectionReason::new(
                        MatchSource::ArchiveNested,
                        "Zip Bomb Ratio Anomaly",
                        format!("Entry {} has abnormal compression ratio {:.1}:1", entry_name, ratio),
                        ThreatSeverity::High,
                        0.75,
                    )],
                });
                continue;
            }
        }

        // Read up to limit
        let read_limit = (uncompressed_size as usize).min(MAX_ENTRY_SCAN_SIZE);
        let mut buffer = Vec::with_capacity(read_limit);
        let mut take_reader = (&mut entry).take(read_limit as u64);
        if let Err(e) = take_reader.read_to_end(&mut buffer) {
            debug!("Error reading zip entry {}: {}", entry_name, e);
            continue;
        }

        let entry_reasons = inspect_entry(&entry_name, &buffer);
        if !entry_reasons.is_empty() {
            matches.push(ArchiveEntryMatch {
                entry_name,
                reasons: entry_reasons,
            });
        }
    }

    Ok(matches)
}
