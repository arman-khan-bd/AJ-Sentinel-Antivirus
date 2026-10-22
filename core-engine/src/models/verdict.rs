use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use super::hashes::FileHashes;
use super::threat::{DetectionReason, ThreatCategory, ThreatSeverity};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Clean,
    Suspicious,
    Malicious,
}

impl Verdict {
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Clean => "clean",
            Verdict::Suspicious => "suspicious",
            Verdict::Malicious => "malicious",
        }
    }

    pub fn is_threat(&self) -> bool {
        matches!(self, Verdict::Suspicious | Verdict::Malicious)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub path: PathBuf,
    pub verdict: Verdict,
    pub confidence: f32,
    pub threat_name: Option<String>,
    pub threat_category: Option<ThreatCategory>,
    pub severity: ThreatSeverity,
    pub detection_reasons: Vec<DetectionReason>,
    pub hashes: FileHashes,
    pub file_size: u64,
    pub file_type: String,
    pub entropy: f64,
    pub is_pe: bool,
    pub is_archive: bool,
    pub authenticode_verified: bool,
    pub authenticode_subject: Option<String>,
    pub scan_duration_ms: u64,
}

impl ScanResult {
    pub fn clean(path: impl AsRef<Path>, hashes: FileHashes, file_size: u64, file_type: impl Into<String>, entropy: f64) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
            verdict: Verdict::Clean,
            confidence: 1.0,
            threat_name: None,
            threat_category: None,
            severity: ThreatSeverity::Info,
            detection_reasons: Vec::new(),
            hashes,
            file_size,
            file_type: file_type.into(),
            entropy,
            is_pe: false,
            is_archive: false,
            authenticode_verified: false,
            authenticode_subject: None,
            scan_duration_ms: 0,
        }
    }
}
