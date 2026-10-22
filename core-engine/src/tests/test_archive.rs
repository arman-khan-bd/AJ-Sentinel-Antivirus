use std::fs::File;
use std::io::Write;
use tempfile::tempdir;
use zip::write::{FileOptions, ZipWriter};
use crate::detection::archive::scan_zip_archive;
use crate::models::{DetectionReason, MatchSource, ThreatSeverity};

#[test]
fn test_zip_archive_inspection() {
    let dir = tempdir().expect("tempdir");
    let zip_path = dir.path().join("test_archive.zip");

    // Create a zip with one clean file and one suspicious file
    {
        let file = File::create(&zip_path).expect("create zip");
        let mut zip = ZipWriter::new(file);
        let options: FileOptions<'_, ()> = FileOptions::default().compression_method(zip::CompressionMethod::Stored);

        zip.start_file("clean.txt", options).expect("entry 1");
        zip.write_all(b"Hello from inside zip archive").expect("write 1");

        zip.start_file("eicar_test.com", options).expect("entry 2");
        zip.write_all(b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*").expect("write 2");

        zip.finish().expect("finish zip");
    }

    let hits = scan_zip_archive(&zip_path, 1, 3, |name, data| {
        let mut reasons = Vec::new();
        if data.windows(5).any(|w| w == b"EICAR") {
            reasons.push(DetectionReason::new(
                MatchSource::ArchiveNested,
                "EICAR In Archive",
                format!("Found EICAR in {}", name),
                ThreatSeverity::Critical,
                1.0,
            ));
        }
        reasons
    }).expect("scan zip");

    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].entry_name, "eicar_test.com");
    assert_eq!(hits[0].reasons[0].severity, ThreatSeverity::Critical);
}
