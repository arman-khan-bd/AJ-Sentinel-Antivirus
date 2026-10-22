use thiserror::Error;

#[derive(Error, Debug)]
pub enum EngineError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("YARA error: {0}")]
    Yara(String),

    #[error("PE parsing error: {0}")]
    PeParse(String),

    #[error("Archive error: {0}")]
    Archive(String),

    #[error("Hashing error: {0}")]
    Hash(String),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Path is excluded by user rule: {0}")]
    PathExcluded(String),

    #[error("Invalid configuration or argument: {0}")]
    InvalidConfig(String),

    #[error("Operation cancelled")]
    Cancelled,
}

pub type Result<T> = std::result::Result<T, EngineError>;
