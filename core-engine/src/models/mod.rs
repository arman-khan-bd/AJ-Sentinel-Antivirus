pub mod exclusions;
pub mod hashes;
pub mod threat;
pub mod verdict;

pub use exclusions::{ExclusionRule, ExclusionType};
pub use hashes::{FileHashes, MalwareHashEntry};
pub use threat::{DetectionReason, MatchSource, ThreatCategory, ThreatSeverity};
pub use verdict::{ScanResult, Verdict};
