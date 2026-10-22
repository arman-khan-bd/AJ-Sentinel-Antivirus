use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MatchSource {
    HashDatabase,
    YaraRule,
    PeHeuristics,
    ScriptHeuristics,
    ArchiveNested,
    AuthenticodeMismatch,
    BehaviorAnomaly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl ThreatSeverity {
    pub fn as_str(&self) -> &'static str {
        match self {
            ThreatSeverity::Info => "info",
            ThreatSeverity::Low => "low",
            ThreatSeverity::Medium => "medium",
            ThreatSeverity::High => "high",
            ThreatSeverity::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThreatCategory {
    EicarTest,
    Ransomware,
    Trojan,
    Backdoor,
    Dropper,
    Worm,
    Spyware,
    Webshell,
    ObfuscatedScript,
    PackerCrypter,
    SuspiciousBehavior,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DetectionReason {
    pub source: MatchSource,
    pub title: String,
    pub details: String,
    pub severity: ThreatSeverity,
    pub confidence_delta: f32,
}

impl DetectionReason {
    pub fn new(
        source: MatchSource,
        title: impl Into<String>,
        details: impl Into<String>,
        severity: ThreatSeverity,
        confidence_delta: f32,
    ) -> Self {
        Self {
            source,
            title: title.into(),
            details: details.into(),
            severity,
            confidence_delta,
        }
    }
}
