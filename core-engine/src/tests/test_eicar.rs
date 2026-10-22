use std::fs::File;
use std::io::Write;
use tempfile::tempdir;

use crate::db::DatabaseManager;
use crate::detection::engine::{DetectionEngine, EngineConfig};
use crate::detection::yara::YaraEngine;
use crate::models::Verdict;

const EICAR_TEST_BYTES: &[u8] = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

#[test]
fn test_eicar_detection_in_memory() {
    let db = DatabaseManager::open_in_memory().expect("db");
    let yara = YaraEngine::new().expect("yara");
    let engine = DetectionEngine::new(db, yara, EngineConfig::default()).expect("engine");

    let result = engine.scan_bytes(EICAR_TEST_BYTES, Some("eicar_test.com"));

    assert_eq!(result.verdict, Verdict::Malicious);
    assert_eq!(result.confidence, 1.0);
    assert!(result.threat_name.is_some());
    let threat_name = result.threat_name.unwrap();
    assert!(threat_name.to_lowercase().contains("eicar"));
}

#[test]
fn test_eicar_detection_on_disk() {
    let dir = tempdir().expect("tempdir");
    let eicar_file = dir.path().join("eicar.com");

    {
        let mut f = File::create(&eicar_file).expect("create file");
        f.write_all(EICAR_TEST_BYTES).expect("write bytes");
    }

    let db = DatabaseManager::open_in_memory().expect("db");
    let yara = YaraEngine::new().expect("yara");
    let engine = DetectionEngine::new(db, yara, EngineConfig::default()).expect("engine");

    let result = engine.scan_file(&eicar_file).expect("scan file");

    assert_eq!(result.verdict, Verdict::Malicious);
    assert_eq!(result.confidence, 1.0);
    assert!(result.threat_name.is_some());
    let name = result.threat_name.unwrap();
    assert!(name.to_lowercase().contains("eicar"));
    assert!(!result.detection_reasons.is_empty());
}

#[test]
fn test_clean_file_detection() {
    let dir = tempdir().expect("tempdir");
    let clean_file = dir.path().join("readme.txt");

    {
        let mut f = File::create(&clean_file).expect("create clean file");
        f.write_all(b"ShieldGuard Antivirus - System Clean Test File\nEverything is operational.").expect("write");
    }

    let db = DatabaseManager::open_in_memory().expect("db");
    let yara = YaraEngine::new().expect("yara");
    let engine = DetectionEngine::new(db, yara, EngineConfig::default()).expect("engine");

    let result = engine.scan_file(&clean_file).expect("scan file");

    assert_eq!(result.verdict, Verdict::Clean);
    assert!(result.confidence >= 0.95);
    assert!(result.threat_name.is_none());
    assert!(result.detection_reasons.is_empty());
}
