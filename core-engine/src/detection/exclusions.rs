use std::path::Path;
use tracing::debug;

use crate::models::{ExclusionRule, ExclusionType};

#[derive(Clone, Default)]
pub struct ExclusionManager {
    rules: Vec<ExclusionRule>,
}

impl ExclusionManager {
    pub fn new(rules: Vec<ExclusionRule>) -> Self {
        Self { rules }
    }

    pub fn is_path_excluded(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy().to_lowercase().replace('/', "\\");

        for rule in &self.rules {
            match rule.rule_type {
                ExclusionType::FilePath => {
                    let rule_val = rule.value.to_lowercase().replace('/', "\\");
                    if path_str == rule_val {
                        debug!("Path {:?} matched FilePath exclusion rule #{}", path, rule.id);
                        return true;
                    }
                }
                ExclusionType::Folder => {
                    let mut rule_val = rule.value.to_lowercase().replace('/', "\\");
                    if !rule_val.ends_with('\\') {
                        rule_val.push('\\');
                    }
                    if path_str.starts_with(&rule_val) || path_str == rule.value.to_lowercase().replace('/', "\\") {
                        debug!("Path {:?} matched Folder exclusion rule #{}", path, rule.id);
                        return true;
                    }
                }
                ExclusionType::Extension => {
                    let ext_target = rule.value.trim_start_matches('.').to_lowercase();
                    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
                        if ext.to_lowercase() == ext_target {
                            debug!("Path {:?} matched Extension exclusion rule #{}", path, rule.id);
                            return true;
                        }
                    }
                }
                ExclusionType::ProcessName => {
                    // For process name exclusions against file paths, check if the filename matches
                    let proc_target = rule.value.to_lowercase();
                    if let Some(file_name) = path.file_name().and_then(|s| s.to_str()) {
                        if file_name.to_lowercase() == proc_target {
                            debug!("Path {:?} matched ProcessName exclusion rule #{}", path, rule.id);
                            return true;
                        }
                    }
                }
            }
        }

        false
    }

    pub fn is_process_excluded(&self, process_name: &str) -> bool {
        let proc_lower = process_name.to_lowercase();
        for rule in &self.rules {
            if rule.rule_type == ExclusionType::ProcessName {
                if rule.value.to_lowercase() == proc_lower {
                    return true;
                }
            }
        }
        false
    }
}
