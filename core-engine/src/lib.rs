//! ShieldGuard Core Antivirus Engine
//! High-performance detection pipeline implementing signature matching,
//! YARA scanning, PE & Script heuristics, archive inspection, and Authenticode validation.

pub mod db;
pub mod detection;
pub mod error;
pub mod models;

#[cfg(test)]
pub mod tests;

// Re-exports
pub use db::DatabaseManager;
pub use detection::{
    analyze_pe, analyze_script, calculate_entropy, check_builtin_hashes, compute_bytes_hashes,
    compute_file_hashes, verify_authenticode, AuthenticodeResult, DetectionEngine, EngineConfig,
    ExclusionManager, YaraEngine, EICAR_SHA256, EMBEDDED_RULES,
};
pub use error::{EngineError, Result};
pub use models::{
    DetectionReason, ExclusionRule, ExclusionType, FileHashes, MalwareHashEntry, MatchSource,
    ScanResult, ThreatCategory, ThreatSeverity, Verdict,
};

pub fn version() -> &'static str {
    "0.1.0"
}
