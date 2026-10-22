-- ShieldGuard Antivirus SQLite Database Schema
-- Version: 1.0.0
-- Target: Windows 10/11 64-bit

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- 1. Application and Engine Settings
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

-- 2. User & System Scan Exclusions (File, Folder, Extension, Process)
CREATE TABLE IF NOT EXISTS exclusions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type TEXT NOT NULL CHECK(rule_type IN ('file', 'folder', 'extension', 'process')),
    value TEXT NOT NULL,
    comment TEXT,
    created_at TEXT NOT NULL
);

-- 3. Local Malware Hash Signatures (Imported from MalwareBazaar & Builtin)
CREATE TABLE IF NOT EXISTS malware_hashes (
    sha256 TEXT PRIMARY KEY,
    threat_name TEXT NOT NULL,
    file_type TEXT,
    severity TEXT NOT NULL DEFAULT 'high',
    source TEXT NOT NULL,
    added_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_malware_hashes_sha256 ON malware_hashes(sha256);

-- 4. Scan Session History
CREATE TABLE IF NOT EXISTS scan_history (
    id TEXT PRIMARY KEY,
    scan_type TEXT NOT NULL, -- 'quick', 'smart', 'deep', 'custom'
    started_at TEXT NOT NULL,
    completed_at TEXT,
    files_scanned INTEGER NOT NULL DEFAULT 0,
    threats_found INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,    -- 'completed', 'cancelled', 'failed'
    summary_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_history_started ON scan_history(started_at DESC);

-- 5. Individual Threat Detections Log
CREATE TABLE IF NOT EXISTS threat_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT,
    file_path TEXT NOT NULL,
    file_hash TEXT NOT NULL,
    threat_name TEXT NOT NULL,
    verdict TEXT NOT NULL,   -- 'clean', 'suspicious', 'malicious'
    confidence REAL NOT NULL,
    severity TEXT NOT NULL,  -- 'low', 'medium', 'high', 'critical'
    detected_at TEXT NOT NULL,
    action_taken TEXT NOT NULL DEFAULT 'logged' -- 'logged', 'quarantined', 'ignored', 'deleted'
);

CREATE INDEX IF NOT EXISTS idx_threat_log_detected_at ON threat_log(detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_log_file_hash ON threat_log(file_hash);

-- 6. Encrypted Quarantine Index (AES-256-GCM Vault metadata)
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
