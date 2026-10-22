use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;
use tracing::{debug, info};

use crate::db::DatabaseManager;
use crate::error::{EngineError, Result};
use crate::models::{
    DetectionReason, FileHashes, MatchSource, ScanResult, ThreatCategory, ThreatSeverity, Verdict,
};
use super::archive::{is_zip_file, scan_zip_archive};
use super::authenticode::verify_authenticode;
use super::exclusions::ExclusionManager;
use super::hash::{check_builtin_hashes, compute_file_hashes};
use super::heuristics::{analyze_pe, analyze_script, calculate_entropy, is_script_extension};
use super::yara::YaraEngine;

#[derive(Clone)]
pub struct EngineConfig {
    pub max_file_size_bytes: u64,
    pub scan_archives: bool,
    pub max_archive_depth: usize,
    pub heuristic_sensitivity: String,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            max_file_size_bytes: 100 * 1024 * 1024, // 100 MB
            scan_archives: true,
            max_archive_depth: 3,
            heuristic_sensitivity: "medium".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct DetectionEngine {
    db: DatabaseManager,
    yara: YaraEngine,
    config: EngineConfig,
    exclusions: ExclusionManager,
}

impl DetectionEngine {
    pub fn new(db: DatabaseManager, yara: YaraEngine, config: EngineConfig) -> Result<Self> {
        let exclusion_rules = db.get_exclusions().unwrap_or_default();
        let exclusions = ExclusionManager::new(exclusion_rules);

        Ok(Self {
            db,
            yara,
            config,
            exclusions,
        })
    }

    /// Reload exclusions from the database
    pub fn reload_exclusions(&mut self) -> Result<()> {
        let rules = self.db.get_exclusions()?;
        self.exclusions = ExclusionManager::new(rules);
        Ok(())
    }

    pub fn yara_engine(&self) -> &YaraEngine {
        &self.yara
    }

    pub fn db_manager(&self) -> &DatabaseManager {
        &self.db
    }

    /// Scans a file on disk through the complete defensive pipeline.
    pub fn scan_file(&self, path: impl AsRef<Path>) -> Result<ScanResult> {
        let path = path.as_ref();
        let start_time = Instant::now();

        // 1. Exclusions check
        if self.exclusions.is_path_excluded(path) {
            debug!("Skipping excluded path: {:?}", path);
            let hashes = FileHashes::new("excluded", "excluded");
            let mut res = ScanResult::clean(path, hashes, 0, "Excluded", 0.0);
            res.detection_reasons.push(DetectionReason::new(
                MatchSource::HashDatabase,
                "Excluded",
                "Path is excluded by user configuration",
                ThreatSeverity::Info,
                0.0,
            ));
            res.scan_duration_ms = start_time.elapsed().as_millis() as u64;
            return Ok(res);
        }

        // 2. Hash computation and file size
        let (hashes, file_size) = match compute_file_hashes(path) {
            Ok(h) => h,
            Err(EngineError::Io(ref err)) if err.raw_os_error() == Some(225) => {
                let hashes = FileHashes::new("blocked_by_os_filter", "blocked_by_os_filter");
                return Ok(ScanResult {
                    path: path.to_path_buf(),
                    verdict: Verdict::Malicious,
                    confidence: 1.0,
                    threat_name: Some("EICAR-Standard-AV-Test-File.Intercepted".to_string()),
                    threat_category: Some(ThreatCategory::EicarTest),
                    severity: ThreatSeverity::Critical,
                    detection_reasons: vec![DetectionReason::new(
                        MatchSource::BehaviorAnomaly,
                        "Threat Intercepted by Antivirus Filter",
                        "File access was blocked with Win32 Error 225 (ERROR_VIRUS_INFECTED)",
                        ThreatSeverity::Critical,
                        1.0,
                    )],
                    hashes,
                    file_size: 0,
                    file_type: "InfectedPayload".to_string(),
                    entropy: 0.0,
                    is_pe: false,
                    is_archive: false,
                    authenticode_verified: false,
                    authenticode_subject: None,
                    scan_duration_ms: start_time.elapsed().as_millis() as u64,
                });
            }
            Err(e) => return Err(e),
        };

        // Skip files that exceed max configured size
        if file_size > self.config.max_file_size_bytes {
            debug!("Skipping file {:?}: size {} exceeds {} MB limit", path, file_size, self.config.max_file_size_bytes / (1024 * 1024));
            let mut res = ScanResult::clean(path, hashes, file_size, "OverSized", 0.0);
            res.scan_duration_ms = start_time.elapsed().as_millis() as u64;
            return Ok(res);
        }

        // 3. Signature Hash Lookup (Built-in + SQLite Malware Hash DB)
        if let Some(builtin) = check_builtin_hashes(&hashes.sha256) {
            info!("Built-in malware signature match for {:?}: {}", path, builtin.threat_name);
            let is_eicar = builtin.sha256.eq_ignore_ascii_case(super::hash::EICAR_SHA256);
            return Ok(ScanResult {
                path: path.to_path_buf(),
                verdict: Verdict::Malicious,
                confidence: 1.0,
                threat_name: Some(builtin.threat_name.clone()),
                threat_category: if is_eicar { Some(ThreatCategory::EicarTest) } else { Some(ThreatCategory::Trojan) },
                severity: ThreatSeverity::Critical,
                detection_reasons: vec![DetectionReason::new(
                    MatchSource::HashDatabase,
                    builtin.threat_name,
                    "Exact cryptographic hash match in ShieldGuard signature database",
                    ThreatSeverity::Critical,
                    1.0,
                )],
                hashes,
                file_size,
                file_type: builtin.file_type.unwrap_or_else(|| "Binary".to_string()),
                entropy: 0.0,
                is_pe: false,
                is_archive: false,
                authenticode_verified: false,
                authenticode_subject: None,
                scan_duration_ms: start_time.elapsed().as_millis() as u64,
            });
        }

        if let Ok(Some(db_match)) = self.db.lookup_hash(&hashes.sha256) {
            info!("Malware database hit for {:?}: {}", path, db_match.threat_name);
            return Ok(ScanResult {
                path: path.to_path_buf(),
                verdict: Verdict::Malicious,
                confidence: 1.0,
                threat_name: Some(db_match.threat_name.clone()),
                threat_category: Some(ThreatCategory::Trojan),
                severity: ThreatSeverity::Critical,
                detection_reasons: vec![DetectionReason::new(
                    MatchSource::HashDatabase,
                    db_match.threat_name,
                    format!("Cryptographic hash match from {}", db_match.source),
                    ThreatSeverity::Critical,
                    1.0,
                )],
                hashes,
                file_size,
                file_type: db_match.file_type.unwrap_or_else(|| "Binary".to_string()),
                entropy: 0.0,
                is_pe: false,
                is_archive: false,
                authenticode_verified: false,
                authenticode_subject: None,
                scan_duration_ms: start_time.elapsed().as_millis() as u64,
            });
        }

        // 4. Read file content for scanning (up to 32MB in memory)
        let read_size = (file_size as usize).min(32 * 1024 * 1024);
        let mut file = File::open(path)?;
        let mut buffer = Vec::with_capacity(read_size);
        file.by_ref().take(read_size as u64).read_to_end(&mut buffer)?;

        let entropy = calculate_entropy(&buffer);
        let mut detection_reasons = Vec::new();
        let mut is_pe = false;
        let mut is_archive = false;
        let mut authenticode_verified = false;
        let mut authenticode_subject = None;
        let mut file_type = "Unknown".to_string();

        // 5. YARA Scanning
        if let Ok(yara_matches) = self.yara.scan_bytes(&buffer) {
            if !yara_matches.is_empty() {
                let reasons = YaraEngine::to_detection_reasons(&yara_matches);
                detection_reasons.extend(reasons);
            }
        }

        // 6. PE Binary Analysis
        if buffer.starts_with(b"MZ") {
            is_pe = true;
            file_type = "PE/Executable".to_string();

            // Authenticode verification
            let auth = verify_authenticode(path);
            if auth.is_trusted() {
                authenticode_verified = true;
                authenticode_subject = auth.publisher_name;
                debug!("File {:?} has trusted Authenticode signature: {:?}", path, authenticode_subject);
            }

            if let Ok(pe_info) = analyze_pe(&buffer) {
                // If the binary is legitimately signed by a trusted publisher, dampen heuristic weight
                if authenticode_verified {
                    for mut r in pe_info.suspicious_reasons {
                        r.confidence_delta *= 0.25; // Reduce heuristic penalty for signed software
                        detection_reasons.push(r);
                    }
                } else {
                    detection_reasons.extend(pe_info.suspicious_reasons);
                }
            }
        }

        // 7. Script Heuristics
        if is_script_extension(path) {
            file_type = "Script".to_string();
            let text = String::from_utf8_lossy(&buffer);
            let script_res = analyze_script(&text, Some(path));
            detection_reasons.extend(script_res.suspicious_reasons);
        }

        // 8. Archive Scanning
        if is_zip_file(path) && self.config.scan_archives {
            is_archive = true;
            file_type = "Archive/ZIP".to_string();

            let yara_clone = self.yara.clone();
            let archive_matches = scan_zip_archive(
                path,
                1,
                self.config.max_archive_depth,
                |entry_name, entry_data| {
                    let mut entry_reasons = Vec::new();
                    if let Ok(matches) = yara_clone.scan_bytes(entry_data) {
                        for m in matches {
                            entry_reasons.push(DetectionReason::new(
                                MatchSource::ArchiveNested,
                                format!("ArchiveEntry: {}", m.threat_name),
                                format!("Rule {} in entry {}", m.rule_name, entry_name),
                                m.severity,
                                0.90,
                            ));
                        }
                    }

                    let entry_path = PathBuf::from(entry_name);
                    if is_script_extension(&entry_path) {
                        let text = String::from_utf8_lossy(entry_data);
                        let s_res = analyze_script(&text, Some(&entry_path));
                        for r in s_res.suspicious_reasons {
                            entry_reasons.push(DetectionReason::new(
                                MatchSource::ArchiveNested,
                                format!("ArchiveEntry: {}", r.title),
                                format!("In {}: {}", entry_name, r.details),
                                r.severity,
                                r.confidence_delta,
                            ));
                        }
                    }
                    entry_reasons
                },
            );

            if let Ok(nested_hits) = archive_matches {
                for hit in nested_hits {
                    detection_reasons.extend(hit.reasons);
                }
            }
        }

        // 9. Composite Verdict Determination
        let mut total_score = 0.0f32;
        let mut max_severity = ThreatSeverity::Info;
        let mut primary_threat_name = None;
        let mut primary_category = None;

        for reason in &detection_reasons {
            total_score += reason.confidence_delta;
            if reason.severity > max_severity {
                max_severity = reason.severity;
            }
            if primary_threat_name.is_none() {
                primary_threat_name = Some(reason.title.clone());
            }
        }

        let (verdict, confidence) = if max_severity == ThreatSeverity::Critical || total_score >= 0.85 {
            (Verdict::Malicious, total_score.min(1.0))
        } else if total_score >= 0.35 || max_severity == ThreatSeverity::Medium {
            (Verdict::Suspicious, total_score.min(0.84))
        } else {
            (Verdict::Clean, 1.0 - total_score.min(0.20))
        };

        if verdict.is_threat() && primary_category.is_none() {
            if is_script_extension(path) {
                primary_category = Some(ThreatCategory::ObfuscatedScript);
            } else if is_pe {
                primary_category = Some(ThreatCategory::Trojan);
            } else {
                primary_category = Some(ThreatCategory::Unknown);
            }
        }

        let elapsed = start_time.elapsed().as_millis() as u64;

        Ok(ScanResult {
            path: path.to_path_buf(),
            verdict,
            confidence,
            threat_name: if verdict.is_threat() { primary_threat_name } else { None },
            threat_category: primary_category,
            severity: max_severity,
            detection_reasons,
            hashes,
            file_size,
            file_type,
            entropy,
            is_pe,
            is_archive,
            authenticode_verified,
            authenticode_subject,
            scan_duration_ms: elapsed,
        })
    }

    /// Scans raw in-memory bytes (for EICAR testing or network payload inspection).
    pub fn scan_bytes(&self, data: &[u8], name: Option<&str>) -> ScanResult {
        let start_time = Instant::now();
        let hashes = super::hash::compute_bytes_hashes(data);
        let path = PathBuf::from(name.unwrap_or("memory_buffer"));
        let file_size = data.len() as u64;
        let entropy = calculate_entropy(data);

        // Check builtin
        if let Some(builtin) = check_builtin_hashes(&hashes.sha256) {
            let is_eicar = builtin.sha256.eq_ignore_ascii_case(super::hash::EICAR_SHA256);
            return ScanResult {
                path,
                verdict: Verdict::Malicious,
                confidence: 1.0,
                threat_name: Some(builtin.threat_name.clone()),
                threat_category: if is_eicar { Some(ThreatCategory::EicarTest) } else { Some(ThreatCategory::Trojan) },
                severity: ThreatSeverity::Critical,
                detection_reasons: vec![DetectionReason::new(
                    MatchSource::HashDatabase,
                    builtin.threat_name,
                    "Cryptographic hash match in builtin database",
                    ThreatSeverity::Critical,
                    1.0,
                )],
                hashes,
                file_size,
                file_type: "MemoryBuffer".to_string(),
                entropy,
                is_pe: false,
                is_archive: false,
                authenticode_verified: false,
                authenticode_subject: None,
                scan_duration_ms: start_time.elapsed().as_millis() as u64,
            };
        }

        let mut detection_reasons = Vec::new();

        // YARA scan
        if let Ok(yara_matches) = self.yara.scan_bytes(data) {
            detection_reasons.extend(YaraEngine::to_detection_reasons(&yara_matches));
        }

        let mut total_score = 0.0f32;
        let mut max_sev = ThreatSeverity::Info;
        let mut threat_name = None;

        for r in &detection_reasons {
            total_score += r.confidence_delta;
            if r.severity > max_sev {
                max_sev = r.severity;
            }
            if threat_name.is_none() {
                threat_name = Some(r.title.clone());
            }
        }

        let (verdict, confidence) = if max_sev == ThreatSeverity::Critical || total_score >= 0.85 {
            (Verdict::Malicious, total_score.min(1.0))
        } else if total_score >= 0.35 {
            (Verdict::Suspicious, total_score)
        } else {
            (Verdict::Clean, 1.0)
        };

        ScanResult {
            path,
            verdict,
            confidence,
            threat_name: if verdict.is_threat() { threat_name } else { None },
            threat_category: if verdict.is_threat() { Some(ThreatCategory::Trojan) } else { None },
            severity: max_sev,
            detection_reasons,
            hashes,
            file_size,
            file_type: "MemoryBuffer".to_string(),
            entropy,
            is_pe: false,
            is_archive: false,
            authenticode_verified: false,
            authenticode_subject: None,
            scan_duration_ms: start_time.elapsed().as_millis() as u64,
        }
    }
}
