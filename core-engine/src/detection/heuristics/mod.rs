pub mod pe;
pub mod script;

pub use pe::{analyze_pe, calculate_entropy, PeAnalysis, SectionInfo};
pub use script::{analyze_script, is_script_extension, ScriptAnalysis};
