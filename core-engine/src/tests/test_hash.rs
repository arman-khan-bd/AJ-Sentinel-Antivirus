use crate::detection::hash::{check_builtin_hashes, compute_bytes_hashes, EICAR_SHA256};

#[test]
fn test_hashing_correctness() {
    let sample = b"ShieldGuard Antivirus Engine Test";
    let hashes = compute_bytes_hashes(sample);

    // Verify SHA-256 format (64 hex characters)
    assert_eq!(hashes.sha256.len(), 64);
    assert_eq!(hashes.blake3.len(), 64);

    // Verify known SHA-256 for string "test"
    let test_hash = compute_bytes_hashes(b"test");
    assert_eq!(
        test_hash.sha256,
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );
}

#[test]
fn test_builtin_eicar_hash_lookup() {
    let match_opt = check_builtin_hashes(EICAR_SHA256);
    assert!(match_opt.is_some());
    let entry = match_opt.unwrap();
    assert_eq!(entry.threat_name, "EICAR-Standard-AV-Test-File");
    assert_eq!(entry.severity, "critical");

    // Case insensitivity
    let upper = EICAR_SHA256.to_uppercase();
    assert!(check_builtin_hashes(&upper).is_some());
}
