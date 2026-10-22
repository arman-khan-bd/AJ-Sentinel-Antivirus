pub mod archive;
pub mod authenticode;
pub mod engine;
pub mod exclusions;
pub mod hash;
pub mod heuristics;
pub mod yara;

pub use archive::{is_zip_file, scan_zip_archive, ArchiveEntryMatch};
pub use authenticode::{is_trusted_publisher_name, verify_authenticode, AuthenticodeResult};
pub use engine::{DetectionEngine, EngineConfig};
pub use exclusions::ExclusionManager;
pub use hash::{check_builtin_hashes, compute_bytes_hashes, compute_file_hashes, EICAR_SHA256};
pub use heuristics::{analyze_pe, analyze_script, calculate_entropy, is_script_extension, PeAnalysis, ScriptAnalysis};
pub use yara::{YaraEngine, YaraMatch, EMBEDDED_RULES};
