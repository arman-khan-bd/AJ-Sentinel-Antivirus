pub const SCHEMA_SQL: &str = r#"
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS exclusions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type TEXT NOT NULL,
    value TEXT NOT NULL,
    comment TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS malware_hashes (
    sha256 TEXT PRIMARY KEY,
    threat_name TEXT NOT NULL,
    file_type TEXT,
    severity TEXT NOT NULL DEFAULT 'high',
    source TEXT NOT NULL,
    added_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_malware_hashes_sha256 ON malware_hashes(sha256);

CREATE TABLE IF NOT EXISTS scan_history (
    id TEXT PRIMARY KEY,
    scan_type TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    threats_found INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,
    summary_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_history_started ON scan_history(started_at DESC);

CREATE TABLE IF NOT EXISTS threat_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    threat_name TEXT NOT NULL,
    verdict TEXT NOT NULL,
    confidence REAL NOT NULL,
    severity TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    action_taken TEXT NOT NULL DEFAULT 'logged'
);

CREATE INDEX IF NOT EXISTS idx_threat_log_detected_at ON threat_log(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_log_file_hash ON threat_log(file_hash);

CREATE TABLE IF NOT EXISTS quarantine_index (
    id TEXT PRIMARY KEY,
    original_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    threat_name TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    quarantined_at TEXT NOT NULL,
    vault_file_name TEXT NOT NULL,
    iv_base64 TEXT NOT NULL,
    tag_base64 TEXT NOT NULL,
    restored INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_quarantine_hash ON quarantine_index(file_hash);
CREATE INDEX IF NOT EXISTS idx_quarantine_restored ON quarantine_index(restored);
"#;

pub const DEFAULT_SETTINGS: &[(&str, &str)] = &[
    ("max_file_size_mb", "100"),
    ("scan_archives", "true"),
    ("archive_max_depth", "3"),
    ("realtime_protection", "true"),
    ("behavior_shield", "true"),
    ("ransomware_shield", "true"),
    ("web_shield", "true"),
    ("auto_quarantine", "false"),
    ("heuristic_sensitivity", "medium"),
    ("signature_version", "2026.10.22.1"),
    ("language", "en"),
    ("low_priority_cpu", "true"),
    ("usb_auto_scan", "true"),
];
