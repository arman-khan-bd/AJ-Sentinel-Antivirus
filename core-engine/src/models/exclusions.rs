use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExclusionType {
    FilePath,
    Folder,
    Extension,
    ProcessName,
}

impl ExclusionType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ExclusionType::FilePath => "file_path",
            ExclusionType::Folder => "folder",
            ExclusionType::Extension => "extension",
            ExclusionType::ProcessName => "process_name",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "file_path" | "file" => Some(ExclusionType::FilePath),
            "folder" | "directory" | "dir" => Some(ExclusionType::Folder),
            "extension" | "ext" => Some(ExclusionType::Extension),
            "process_name" | "process" => Some(ExclusionType::ProcessName),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExclusionRule {
    pub id: i64,
    pub rule_type: ExclusionType,
    pub value: String,
    pub comment: Option<String>,
    pub created_at: String,
}
