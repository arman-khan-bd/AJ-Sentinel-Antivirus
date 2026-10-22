use crate::db::DatabaseManager;
use crate::models::{ExclusionType, MalwareHashEntry};

#[test]
fn test_database_initialization_and_operations() {
    let db = DatabaseManager::open_in_memory().expect("in-memory db");

    // Test default settings
    let lang = db.get_setting("language").expect("get setting");
    assert_eq!(lang, Some("en".to_string()));

    // Test updating settings
    db.set_setting("language", "bn").expect("set setting");
    assert_eq!(db.get_setting("language").unwrap(), Some("bn".to_string()));

    // Test malware hash insertion and lookup
    let hash_entry = MalwareHashEntry {
        sha256: "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string(),
        threat_name: "Trojan.Win32.TestPayload".to_string(),
        file_type: Some("EXE".to_string()),
        severity: "critical".to_string(),
        source: "UnitTests".to_string(),
        added_at: "2026-01-01T00:00:00Z".to_string(),
    };

    db.insert_malware_hash(&hash_entry).expect("insert hash");
    let looked_up = db.lookup_hash("AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899").expect("lookup");
    assert!(looked_up.is_some());
    assert_eq!(looked_up.unwrap().threat_name, "Trojan.Win32.TestPayload");

    // Test exclusions
    let id = db.add_exclusion(ExclusionType::Folder, "C:\\TestDir", Some("Safe test folder")).expect("add excl");
    let exclusions = db.get_exclusions().expect("get excl");
    assert_eq!(exclusions.len(), 1);
    assert_eq!(exclusions[0].value, "C:\\TestDir");

    let removed = db.remove_exclusion(id).expect("remove excl");
    assert!(removed);
    assert_eq!(db.get_exclusions().unwrap().len(), 0);

    // Test threat logging
    let threat_id = db.log_threat(
        Some("scan-123"),
        "C:\\Temp\\evil.exe",
        "aabbcc",
        "Trojan.Test",
        "malicious",
        0.98,
        "critical",
        "quarantined",
    ).expect("log threat");
    assert!(threat_id > 0);
}
