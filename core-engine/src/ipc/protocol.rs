use std::collections::HashMap;
use serde::{Deserialize, Serialize};

pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\shieldguard_ipc";

/// Top-level IPC message wrapper carrying a unique correlation ID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "payload")]
pub enum IpcMessage {
    Request(IpcEnvelope<IpcRequest>),
    Response(IpcEnvelope<IpcResponse>),
    Event(IpcEvent),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IpcEnvelope<T> {
    pub id: String,
    pub body: T,
}

impl<T> IpcEnvelope<T> {
    pub fn new(id: impl Into<String>, body: T) -> Self {
        Self {
            id: id.into(),
            body,
        }
    }
}

/// Commands issued from UI or CLI to the Engine Service
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", content = "params")]
pub enum IpcRequest {
    /// Ping service for healthcheck
    Ping,
    /// Query global protection status and module state
    GetStatus,
    /// Start a new antivirus scan
    StartScan {
        scan_type: ScanType,
        target_path: Option<String>,
    },
    /// Pause an in-progress scan
    PauseScan { scan_id: String },
    /// Resume a paused scan
    ResumeScan { scan_id: String },
    /// Cancel an in-progress scan
    CancelScan { scan_id: String },
    /// Get current progress of a specific scan
    GetScanProgress { scan_id: String },
    /// Fetch all quarantined files
    ListQuarantine,
    /// Restore a quarantined file back to original location
    RestoreQuarantine { id: String },
    /// Permanently delete a quarantined file
    DeleteQuarantine { id: String },
    /// Toggle or pause a protection shield
    SetShieldStatus {
        shield: ShieldType,
        enabled: bool,
        pause_duration_secs: Option<u64>,
    },
    /// Retrieve all settings
    GetSettings,
    /// Update engine settings key-value pair
    UpdateSetting { key: String, value: String },
    /// Query exclusions
    GetExclusions,
    /// Add an exclusion rule
    AddExclusion { rule_type: String, value: String, comment: Option<String> },
    /// Remove an exclusion rule
    RemoveExclusion { id: i64 },
    /// Trigger signature update check
    CheckUpdates,
    /// Subscribe to live event stream
    SubscribeEvents,
}

/// Response returned from the Engine Service to the caller
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "status", content = "data")]
pub enum IpcResponse {
    Pong,
    Status(EngineStatus),
    ScanStarted { scan_id: String },
    ScanProgress(ScanProgressEvent),
    ScanFinished(ScanSummary),
    QuarantineList(Vec<QuarantineItemSummary>),
    Settings(HashMap<String, String>),
    Exclusions(Vec<ExclusionSummary>),
    UpdateCheckResult { has_update: bool, latest_version: String },
    Success { message: String },
    Error { code: u32, message: String },
}

/// Live push events streamed over the named pipe
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "event_type", content = "data")]
pub enum IpcEvent {
    /// Real-time progress update during an active scan
    ScanProgress(ScanProgressEvent),
    /// A threat was identified during real-time monitoring or active scan
    ThreatDetected(ThreatDetectionEvent),
    /// State of a real-time shield changed
    ShieldStatusChanged {
        shield: ShieldType,
        enabled: bool,
        paused_until: Option<String>,
    },
    /// Removable drive connected (USB/SD Card/External HDD)
    RemovableDriveInserted {
        drive_letter: String,
        drive_type: String,
        volume_name: String,
        is_trusted: bool,
    },
    /// Signature or program update event
    UpdateProgress {
        stage: String,
        percent: u8,
        version: String,
    },
    /// General system or security notification for UI toast
    Notification {
        title: String,
        body: String,
        level: NotificationLevel,
    },
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ScanType {
    Quick,
    Smart,
    Deep,
    Custom,
    Drive,
    BootTime,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum ShieldType {
    FileShield,
    BehaviorShield,
    RansomwareShield,
    WebShield,
    MailDownloadShield,
    UsbShield,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NotificationLevel {
    Info,
    Success,
    Warning,
    Danger,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EngineStatus {
    pub is_running: bool,
    pub engine_version: String,
    pub signature_version: String,
    pub last_scan_time: Option<String>,
    pub threats_blocked_total: u64,
    pub active_shields: HashMap<ShieldType, bool>,
    pub active_scans_count: usize,
    pub silent_mode: bool,
    pub memory_usage_mb: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanProgressEvent {
    pub scan_id: String,
    pub scan_type: ScanType,
    pub files_scanned: usize,
    pub threats_found: usize,
    pub current_file: String,
    pub elapsed_ms: u64,
    pub estimated_remaining_ms: Option<u64>,
    pub speed_files_per_sec: f32,
    pub stage: String,
    pub is_paused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ThreatDetectionEvent {
    pub scan_id: Option<String>,
    pub file_path: String,
    pub file_hash: String,
    pub threat_name: String,
    pub severity: String,
    pub confidence: f32,
    pub detected_at: String,
    pub action_taken: String,
    pub reason_description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScanSummary {
    pub scan_id: String,
    pub scan_type: ScanType,
    pub started_at: String,
    pub completed_at: String,
    pub files_scanned: usize,
    pub threats_found: usize,
    pub threats_resolved: usize,
    pub duration_seconds: f32,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct QuarantineItemSummary {
    pub id: String,
    pub original_path: String,
    pub file_hash: String,
    pub threat_name: String,
    pub file_size: u64,
    pub quarantined_at: String,
    pub restored: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExclusionSummary {
    pub id: i64,
    pub rule_type: String,
    pub value: String,
    pub comment: Option<String>,
    pub created_at: String,
}
