use std::fs;
use std::path::Path;
use std::sync::{Arc, RwLock};
use tracing::{debug, info, warn};
use yara_x::{Compiler, MetaValue, Rules, Scanner};

use crate::error::{EngineError, Result};
use crate::models::{DetectionReason, MatchSource, ThreatSeverity};

pub const EMBEDDED_RULES: &str = r#"
rule EICAR_Test_File {
    meta:
        description = "Standard EICAR Antivirus Test File"
        threat_name = "EICAR-Standard-AV-Test-File"
        severity = "critical"
        category = "eicar_test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}

rule Suspicious_PowerShell_Cradle {
    meta:
        description = "Obfuscated PowerShell Download Cradle"
        threat_name = "Trojan.Script.PowerShellCradle"
        severity = "high"
        category = "obfuscated_script"
    strings:
        $enc1 = "-enc" nocase
        $enc2 = "-encodedcommand" nocase
        $down1 = "Net.WebClient" nocase
        $down2 = "DownloadString" nocase
        $down3 = "DownloadFile" nocase
        $iex1 = "Invoke-Expression" nocase
        $iex2 = "iex" nocase
        $amsi1 = "amsiInitFailed" nocase
        $amsi2 = "AmsiUtils" nocase
    condition:
        ($enc1 or $enc2) and ($down1 or $down2 or $down3 or $iex1 or $iex2) or ($amsi1 or $amsi2)
}

rule Suspicious_Webshell_PHP {
    meta:
        description = "PHP Backdoor Webshell Indicator"
        threat_name = "Backdoor.PHP.Webshell"
        severity = "high"
        category = "webshell"
    strings:
        $s1 = "eval(base64_decode" nocase
        $s2 = "assert($_POST" nocase
        $s3 = "system($_GET" nocase
        $s4 = "passthru($_POST" nocase
        $s5 = "shell_exec(" nocase
    condition:
        any of ($s1, $s2, $s3, $s4, $s5)
}

rule Ransomware_Note_Indicators {
    meta:
        description = "Ransomware generic payment note keywords"
        threat_name = "Ransomware.Generic.Note"
        severity = "high"
        category = "ransomware"
    strings:
        $r1 = "all your files have been encrypted" nocase
        $r2 = "your personal decryption key" nocase
        $r3 = "restore your files" nocase
        $r4 = ".onion" nocase
        $r5 = "bitcoin" nocase
    condition:
        ($r1 or $r2) and ($r3 or $r4 or $r5)
}

rule Mimikatz_Artifacts {
    meta:
        description = "Mimikatz credential dumping artifacts"
        threat_name = "HackTool.Win64.Mimikatz"
        severity = "critical"
        category = "trojan"
    strings:
        $m1 = "sekurlsa::logonpasswords" ascii wide nocase
        $m2 = "lsadump::sam" ascii wide nocase
        $m3 = "privilege::debug" ascii wide nocase
    condition:
        any of ($m1, $m2, $m3)
}
"#;

#[derive(Clone)]
pub struct YaraMatch {
    pub rule_name: String,
    pub threat_name: String,
    pub severity: ThreatSeverity,
    pub description: String,
}

#[derive(Clone)]
pub struct YaraEngine {
    rules: Arc<RwLock<Rules>>,
}

impl YaraEngine {
    /// Initializes YARA engine with built-in embedded rules.
    pub fn new() -> Result<Self> {
        let mut compiler = Compiler::new();
        compiler
            .add_source(EMBEDDED_RULES)
            .map_err(|e| EngineError::Yara(format!("Failed to compile embedded YARA rules: {}", e)))?;

        let rules = compiler.build();
        info!("YaraEngine initialized with embedded rule set");
        Ok(Self {
            rules: Arc::new(RwLock::new(rules)),
        })
    }

    /// Loads and compiles all .yar and .yara rule files from a directory, along with embedded rules.
    pub fn load_from_dir(rules_dir: impl AsRef<Path>) -> Result<Self> {
        let mut compiler = Compiler::new();

        // Always add embedded rules first
        compiler
            .add_source(EMBEDDED_RULES)
            .map_err(|e| EngineError::Yara(format!("Failed to compile embedded rules: {}", e)))?;

        let dir = rules_dir.as_ref();
        if dir.exists() && dir.is_dir() {
            let mut custom_count = 0;
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                        if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara") {
                            match fs::read_to_string(&path) {
                                Ok(content) => {
                                    if let Err(e) = compiler.add_source(content.as_str()) {
                                        warn!("Error compiling YARA rule file {:?}: {}", path, e);
                                    } else {
                                        custom_count += 1;
                                    }
                                }
                                Err(e) => warn!("Failed to read YARA rule file {:?}: {}", path, e),
                            }
                        }
                    }
                }
            }
            info!("Loaded {} custom YARA rule files from {:?}", custom_count, dir);
        } else {
            debug!("Rules directory {:?} not found, using embedded rules only", dir);
        }

        let rules = compiler.build();
        Ok(Self {
            rules: Arc::new(RwLock::new(rules)),
        })
    }

    /// Hot-reload YARA rules from the specified directory without interrupting active scans.
    pub fn hot_reload(&self, rules_dir: impl AsRef<Path>) -> Result<usize> {
        let mut compiler = Compiler::new();
        compiler
            .add_source(EMBEDDED_RULES)
            .map_err(|e| EngineError::Yara(format!("Failed to compile embedded rules during hot reload: {}", e)))?;

        let dir = rules_dir.as_ref();
        let mut custom_count = 0;
        if dir.exists() && dir.is_dir() {
            if let Ok(entries) = fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                        if ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara") {
                            if let Ok(content) = fs::read_to_string(&path) {
                                if let Ok(_) = compiler.add_source(content.as_str()) {
                                    custom_count += 1;
                                }
                            }
                        }
                    }
                }
            }
        }

        let new_rules = compiler.build();
        {
            let mut write_guard = self.rules.write().map_err(|_| {
                EngineError::Yara("Failed to acquire write lock on YARA rules".to_string())
            })?;
            *write_guard = new_rules;
        }

        info!("YARA rules hot-reloaded successfully. {} custom files active", custom_count);
        Ok(custom_count)
    }

    /// Scans an in-memory byte buffer against the active YARA ruleset.
    pub fn scan_bytes(&self, data: &[u8]) -> Result<Vec<YaraMatch>> {
        let rules_guard = self.rules.read().map_err(|_| {
            EngineError::Yara("Failed to acquire read lock on YARA rules".to_string())
        })?;

        let mut scanner = Scanner::new(&rules_guard);
        let scan_results = scanner
            .scan(data)
            .map_err(|e| EngineError::Yara(format!("YARA scan execution failed: {:?}", e)))?;

        let mut matches = Vec::new();
        for rule in scan_results.matching_rules() {
            let identifier = rule.identifier().to_string();
            let mut threat_name = format!("YARA.{}", identifier);
            let mut severity = ThreatSeverity::High;
            let mut description = format!("Matched YARA rule: {}", identifier);

            // Parse metadata if available
            for (key, val) in rule.metadata() {
                match key {
                    "threat_name" => {
                        if let MetaValue::String(s) = val {
                            threat_name = s.to_string();
                        }
                    }
                    "severity" => {
                        if let MetaValue::String(s) = val {
                            match s.to_lowercase().as_str() {
                                "critical" => severity = ThreatSeverity::Critical,
                                "high" => severity = ThreatSeverity::High,
                                "medium" => severity = ThreatSeverity::Medium,
                                "low" => severity = ThreatSeverity::Low,
                                _ => {}
                            }
                        }
                    }
                    "description" => {
                        if let MetaValue::String(s) = val {
                            description = s.to_string();
                        }
                    }
                    _ => {}
                }
            }

            matches.push(YaraMatch {
                rule_name: identifier,
                threat_name,
                severity,
                description,
            });
        }

        Ok(matches)
    }

    /// Converts YARA matches into standardized DetectionReason items.
    pub fn to_detection_reasons(matches: &[YaraMatch]) -> Vec<DetectionReason> {
        matches
            .iter()
            .map(|m| {
                let delta = match m.severity {
                    ThreatSeverity::Critical => 1.0,
                    ThreatSeverity::High => 0.85,
                    ThreatSeverity::Medium => 0.60,
                    ThreatSeverity::Low => 0.35,
                    ThreatSeverity::Info => 0.10,
                };
                DetectionReason::new(
                    MatchSource::YaraRule,
                    &m.threat_name,
                    format!("{}: {}", m.rule_name, m.description),
                    m.severity,
                    delta,
                )
            })
            .collect()
    }
}
