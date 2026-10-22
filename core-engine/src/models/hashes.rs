use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileHashes {
    pub sha256: String,
    pub blake3: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
}

impl FileHashes {
    pub fn new(sha256: impl Into<String>, blake3: impl Into<String>) -> Self {
        Self {
            sha256: sha256.into().to_lowercase(),
            blake3: blake3.into().to_lowercase(),
            md5: None,
        }
    }

    pub fn with_md5(mut self, md5: impl Into<String>) -> Self {
        self.md5 = Some(md5.into().to_lowercase());
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MalwareHashEntry {
    pub sha256: String,
    pub threat_name: String,
    pub file_type: Option<String>,
    pub severity: String,
    pub source: String,
    pub added_at: String,
}
