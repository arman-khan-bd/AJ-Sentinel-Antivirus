use std::path::Path;
use crate::detection::exclusions::ExclusionManager;
use crate::models::{ExclusionRule, ExclusionType};

#[test]
fn test_exclusion_matching() {
    let rules = vec![
        ExclusionRule {
            id: 1,
            rule_type: ExclusionType::FilePath,
            value: "C:\\Safe\\tool.exe".to_string(),
            comment: None,
            created_at: "2026-01-01".to_string(),
        },
        ExclusionRule {
            id: 2,
            rule_type: ExclusionType::Folder,
            value: "D:\\DevProjects".to_string(),
            comment: None,
            created_at: "2026-01-01".to_string(),
        },
        ExclusionRule {
            id: 3,
            rule_type: ExclusionType::Extension,
            value: ".iso".to_string(),
            comment: None,
            created_at: "2026-01-01".to_string(),
        },
        ExclusionRule {
            id: 4,
            rule_type: ExclusionType::ProcessName,
            value: "devenv.exe".to_string(),
            comment: None,
            created_at: "2026-01-01".to_string(),
        },
    ];

    let mgr = ExclusionManager::new(rules);

    // Exact file path
    assert!(mgr.is_path_excluded(Path::new("c:/safe/tool.exe")));
    assert!(mgr.is_path_excluded(Path::new("C:\\Safe\\tool.exe")));
    assert!(!mgr.is_path_excluded(Path::new("C:\\Safe\\other.exe")));

    // Directory prefix
    assert!(mgr.is_path_excluded(Path::new("D:\\DevProjects\\app\\main.rs")));
    assert!(mgr.is_path_excluded(Path::new("d:/devprojects/sub/test.exe")));
    assert!(!mgr.is_path_excluded(Path::new("D:\\Other\\test.exe")));

    // Extension
    assert!(mgr.is_path_excluded(Path::new("E:\\images\\backup.iso")));
    assert!(mgr.is_path_excluded(Path::new("E:\\images\\backup.ISO")));
    assert!(!mgr.is_path_excluded(Path::new("E:\\images\\backup.exe")));

    // Process name
    assert!(mgr.is_process_excluded("devenv.exe"));
    assert!(mgr.is_process_excluded("DEVENV.EXE"));
    assert!(!mgr.is_process_excluded("malware.exe"));
}
