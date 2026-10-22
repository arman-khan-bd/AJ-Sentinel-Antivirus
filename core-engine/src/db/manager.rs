use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::{Arc, Mutex};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use tracing::{debug, info};

use crate::error::Result;
use crate::models::{ExclusionRule, ExclusionType, MalwareHashEntry};
use super::schema::{DEFAULT_SETTINGS, SCHEMA_SQL};

#[derive(Clone)]
pub struct DatabaseManager {
    conn: Arc<Mutex<Connection>>,
}

impl DatabaseManager {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let conn = Connection::open(path)?;
        let mgr = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        mgr.initialize_schema()?;
        Ok(mgr)
    }

    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        let mgr = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        mgr.initialize_schema()?;
        Ok(mgr)
    }

    pub fn initialize_schema(&self) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(SCHEMA_SQL)?;

        // Seed default settings if missing
        let now = Utc::now().to_rfc3339();
        for (k, v) in DEFAULT_SETTINGS {
            conn.execute(
                "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
                params![k, v, now],
            )?;
        }
        info!("Database schema initialized and default settings verified");
        Ok(())
    }

    // -------------------------------------------------------------
    // Malware Hash Lookup and Import
    // -------------------------------------------------------------

    pub fn lookup_hash(&self, sha256: &str) -> Result<Option<MalwareHashEntry>> {
        let sha256_lower = sha256.trim().to_lowercase();
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT sha256, threat_name, file_type, severity, source, added_at FROM malware_hashes WHERE sha256 = ?1",
        )?;

        let result = stmt
            .query_row(params![sha256_lower], |row| {
                Ok(MalwareHashEntry {
                    sha256: row.get(0)?,
                    threat_name: row.get(1)?,
                    file_type: row.get(2)?,
                    severity: row.get(3)?,
                    source: row.get(4)?,
                    added_at: row.get(5)?,
                })
            })
            .optional()?;

        Ok(result)
    }

    pub fn insert_malware_hash(&self, entry: &MalwareHashEntry) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR REPLACE INTO malware_hashes (sha256, threat_name, file_type, severity, source, added_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.sha256.to_lowercase(),
                entry.threat_name,
                entry.file_type,
                entry.severity,
                entry.source,
                entry.added_at,
            ],
        )?;
        Ok(())
    }

    pub fn batch_import_hashes(&self, entries: &[MalwareHashEntry]) -> Result<usize> {
        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let mut imported = 0;

        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO malware_hashes (sha256, threat_name, file_type, severity, source, added_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            )?;

            for e in entries {
                stmt.execute(params![
                    e.sha256.to_lowercase(),
                    e.threat_name,
                    e.file_type,
                    e.severity,
                    e.source,
                    e.added_at,
                ])?;
                imported += 1;
            }
        }

        tx.commit()?;
        info!("Batch imported {} malware hash entries", imported);
        Ok(imported)
    }

    /// Import MalwareBazaar public feed format (CSV)
    /// Format lines: First_seen_utc,SHA256_hash,MD5_hash,SHA1_hash,Reporter,File_name,File_type_guess,MIME_type,Signature,ClamAV,VT%
    pub fn import_malware_bazaar_csv(&self, path: impl AsRef<Path>) -> Result<usize> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);
        let mut entries = Vec::new();
        let now = Utc::now().to_rfc3339();

        for line_res in reader.lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            let parts: Vec<&str> = trimmed.split(',').map(|s| s.trim().trim_matches('"')).collect();
            // Expected MalwareBazaar CSV columns:
            // 0: first_seen_utc, 1: sha256_hash, 2: md5_hash, 3: sha1_hash, 4: reporter,
            // 5: file_name, 6: file_type_guess, 7: mime_type, 8: signature (malware family)
            if parts.len() >= 9 {
                let sha256 = parts[1].to_string();
                if sha256.len() == 64 {
                    let sig = if parts[8].is_empty() || parts[8] == "n/a" {
                        if !parts[5].is_empty() {
                            format!("Trojan.Generic.{}", parts[5])
                        } else {
                            "Malware.Generic.MalwareBazaar".to_string()
                        }
                    } else {
                        parts[8].to_string()
                    };

                    entries.push(MalwareHashEntry {
                        sha256,
                        threat_name: sig,
                        file_type: Some(parts[6].to_string()),
                        severity: "high".to_string(),
                        source: "MalwareBazaar".to_string(),
                        added_at: now.clone(),
                    });
                }
            }

            if entries.len() >= 5000 {
                self.batch_import_hashes(&entries)?;
                entries.clear();
            }
        }

        let mut count = 0;
        if !entries.is_empty() {
            count = self.batch_import_hashes(&entries)?;
        }
        Ok(count)
    }

    // -------------------------------------------------------------
    // Exclusions Management
    // -------------------------------------------------------------

    pub fn get_exclusions(&self) -> Result<Vec<ExclusionRule>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, rule_type, value, comment, created_at FROM exclusions ORDER BY id ASC")?;

        let rows = stmt.query_map([], |row| {
            let type_str: String = row.get(1)?;
            let rule_type = ExclusionType::from_str(&type_str).unwrap_or(ExclusionType::FilePath);
            Ok(ExclusionRule {
                id: row.get(0)?,
                rule_type,
                value: row.get(2)?,
                comment: row.get(3)?,
                created_at: row.get(4)?,
            })
        })?;

        let mut exclusions = Vec::new();
        for r in rows {
            exclusions.push(r?);
        }
        Ok(exclusions)
    }

    pub fn add_exclusion(&self, rule_type: ExclusionType, value: &str, comment: Option<&str>) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO exclusions (rule_type, value, comment, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![rule_type.as_str(), value.trim(), comment, now],
        )?;
        let id = conn.last_insert_rowid();
        info!("Added exclusion rule #{} [{}]: {}", id, rule_type.as_str(), value);
        Ok(id)
    }

    pub fn remove_exclusion(&self, id: i64) -> Result<bool> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute("DELETE FROM exclusions WHERE id = ?1", params![id])?;
        Ok(rows > 0)
    }

    // -------------------------------------------------------------
    // Scan History & Threat Logging
    // -------------------------------------------------------------

    pub fn record_scan_start(&self, scan_id: &str, scan_type: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO scan_history (id, scan_type, started_at, status) VALUES (?1, ?2, ?3, 'running')",
            params![scan_id, scan_type, now],
        )?;
        Ok(())
    }

    pub fn record_scan_finish(
        &self,
        scan_id: &str,
        files_scanned: u64,
        threats_found: u64,
        status: &str,
        summary_json: Option<&str>,
    ) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "UPDATE scan_history SET completed_at = ?1, files_scanned = ?2, threats_found = ?3, status = ?4, summary_json = ?5 WHERE id = ?6",
            params![now, files_scanned as i64, threats_found as i64, status, summary_json, scan_id],
        )?;
        Ok(())
    }

    pub fn log_threat(
        &self,
        scan_id: Option<&str>,
        file_path: &str,
        file_hash: &str,
        threat_name: &str,
        verdict: &str,
        confidence: f32,
        severity: &str,
        action_taken: &str,
    ) -> Result<i64> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO threat_log (scan_id, file_path, file_hash, threat_name, verdict, confidence, severity, detected_at, action_taken)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![scan_id, file_path, file_hash, threat_name, verdict, confidence as f64, severity, now, action_taken],
        )?;
        let id = conn.last_insert_rowid();
        info!("Threat logged #{}: {} ({}) at {}", id, threat_name, verdict, file_path);
        Ok(id)
    }

    // -------------------------------------------------------------
    // Settings
    // -------------------------------------------------------------

    pub fn get_setting(&self, key: &str) -> Result<Option<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT value FROM settings WHERE key = ?1")?;
        let res = stmt.query_row(params![key], |row| row.get(0)).optional()?;
        Ok(res)
    }

    pub fn set_setting(&self, key: &str, value: &str) -> Result<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value, updated_at) VALUES (?1, ?2, ?3)",
            params![key, value, now],
        )?;
        debug!("Setting updated: {} = {}", key, value);
        Ok(())
    }

    pub fn get_all_settings(&self) -> Result<HashMap<String, String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT key, value FROM settings")?;
        let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;

        let mut map = HashMap::new();
        for r in rows {
            let (k, v) = r?;
            map.insert(k, v);
        }
        Ok(map)
    }
}
