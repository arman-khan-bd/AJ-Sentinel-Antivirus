use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;
use sha2::{Digest, Sha256};
use blake3::Hasher as Blake3Hasher;

use crate::error::Result;
use crate::models::{FileHashes, MalwareHashEntry};

pub const EICAR_SHA256: &str = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";

/// Computes SHA-256 and BLAKE3 hashes in a single streaming read pass.
pub fn compute_file_hashes(path: impl AsRef<Path>) -> Result<(FileHashes, u64)> {
    let file = File::open(path)?;
    let mut reader = BufReader::with_capacity(64 * 1024, file);
    let mut sha256 = Sha256::new();
    let mut blake3 = Blake3Hasher::new();

    let mut buffer = [0u8; 64 * 1024];
    let mut total_bytes = 0u64;

    loop {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        sha256.update(&buffer[..bytes_read]);
        blake3.update(&buffer[..bytes_read]);
        total_bytes += bytes_read as u64;
    }

    let sha256_hex = format!("{:x}", sha256.finalize());
    let blake3_hex = blake3.finalize().to_hex().to_string();

    Ok((FileHashes::new(sha256_hex, blake3_hex), total_bytes))
}

/// Computes SHA-256 and BLAKE3 hashes for an in-memory byte slice.
pub fn compute_bytes_hashes(bytes: &[u8]) -> FileHashes {
    let mut sha256 = Sha256::new();
    sha256.update(bytes);
    let sha256_hex = format!("{:x}", sha256.finalize());

    let blake3_hex = blake3::hash(bytes).to_hex().to_string();

    FileHashes::new(sha256_hex, blake3_hex)
}

/// Checks if a SHA-256 hash matches built-in critical signatures (such as EICAR).
pub fn check_builtin_hashes(sha256: &str) -> Option<MalwareHashEntry> {
    if sha256.eq_ignore_ascii_case(EICAR_SHA256) {
        return Some(MalwareHashEntry {
            sha256: EICAR_SHA256.to_string(),
            threat_name: "EICAR-Standard-AV-Test-File".to_string(),
            file_type: Some("Text/COM".to_string()),
            severity: "critical".to_string(),
            source: "Builtin-Signatures".to_string(),
            added_at: "2026-01-01T00:00:00Z".to_string(),
        });
    }
    None
}
