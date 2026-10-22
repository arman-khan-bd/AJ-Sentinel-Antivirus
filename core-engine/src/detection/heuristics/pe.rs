use std::collections::HashSet;
use goblin::pe::PE;
use tracing::debug;

use crate::error::{EngineError, Result};
use crate::models::{DetectionReason, MatchSource, ThreatSeverity};

pub const KNOWN_PACKER_SECTIONS: &[&str] = &[
    ".upx0", ".upx1", ".upx2", "upx!", ".aspack", ".adata", ".mpress1", ".mpress2",
    ".themida", ".vmp0", ".vmp1", ".vmp2", "pecompact", "nsp0", "nsp1", "nsp2",
    ".fsg", ".petite", ".pack", ".crypter", ".stub",
];

pub const SUSPICIOUS_INJECTION_APIS: &[&str] = &[
    "virtualallocex",
    "writeprocessmemory",
    "createremotethread",
    "ntunmapviewofsection",
    "queueuserapc",
    "setthreadcontext",
    "resumethread",
];

pub const SUSPICIOUS_SPYWARE_APIS: &[&str] = &[
    "setwindowshookexa",
    "setwindowshookexw",
    "getasynckeystate",
    "getkeystate",
    "registerhotkey",
];

pub const SUSPICIOUS_EVASION_APIS: &[&str] = &[
    "isdebuggerpresent",
    "checkremotedebuggerpresent",
    "ntqueryinformationprocess",
    "adjusttokenprivileges",
];

#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub name: String,
    pub virtual_size: u32,
    pub raw_size: u32,
    pub entropy: f64,
    pub is_writable: bool,
    pub is_executable: bool,
    pub is_writable_and_executable: bool,
}

#[derive(Debug, Clone)]
pub struct PeAnalysis {
    pub is_valid_pe: bool,
    pub is_64bit: bool,
    pub overall_entropy: f64,
    pub entry_point: usize,
    pub sections: Vec<SectionInfo>,
    pub imported_functions: Vec<String>,
    pub imported_dlls: Vec<String>,
    pub suspicious_reasons: Vec<DetectionReason>,
    pub heuristic_score: f32, // 0.0 to 1.0
}

/// Calculate Shannon entropy of a byte slice: range 0.0 (uniform) to 8.0 (completely random / encrypted).
pub fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut counts = [0usize; 256];
    for &b in data {
        counts[b as usize] += 1;
    }

    let len_f = data.len() as f64;
    let mut entropy = 0.0;

    for &count in counts.iter() {
        if count > 0 {
            let p = count as f64 / len_f;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Analyzes a PE binary buffer for suspicious heuristics, packing, entropy, and imports.
pub fn analyze_pe(data: &[u8]) -> Result<PeAnalysis> {
    let pe = PE::parse(data).map_err(|e| EngineError::PeParse(format!("Failed to parse PE: {}", e)))?;

    let overall_entropy = calculate_entropy(data);
    let mut sections_info = Vec::new();
    let mut suspicious_reasons = Vec::new();
    let mut score = 0.0f32;

    let is_64bit = pe.is_64;
    let entry_point = pe.entry;

    // Check sections
    let mut has_high_entropy_section = false;
    let mut has_wx_section = false;
    let mut has_known_packer_name = false;
    let mut entry_in_last_section = false;
    let num_sections = pe.sections.len();

    for (idx, sec) in pe.sections.iter().enumerate() {
        let name_str = sec.name().unwrap_or("").to_lowercase();
        let raw_offset = sec.pointer_to_raw_data as usize;
        let raw_size = sec.size_of_raw_data as usize;

        let sec_data = if raw_offset < data.len() {
            let end = (raw_offset + raw_size).min(data.len());
            &data[raw_offset..end]
        } else {
            &[]
        };

        let sec_entropy = calculate_entropy(sec_data);

        // Windows PE section characteristics
        const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
        const IMAGE_SCN_MEM_WRITE: u32 = 0x8000_0000;

        let is_executable = (sec.characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
        let is_writable = (sec.characteristics & IMAGE_SCN_MEM_WRITE) != 0;
        let is_wx = is_executable && is_writable;

        if is_wx {
            has_wx_section = true;
        }

        if sec_entropy > 7.15 && raw_size > 4096 {
            has_high_entropy_section = true;
        }

        for packer_name in KNOWN_PACKER_SECTIONS {
            if name_str.contains(packer_name) {
                has_known_packer_name = true;
                break;
            }
        }

        // Check if entry point is in the last section
        if idx == num_sections - 1 && num_sections > 1 {
            let sec_start = sec.virtual_address as usize;
            let sec_end = sec_start + sec.virtual_size.max(sec.size_of_raw_data) as usize;
            if entry_point >= sec_start && entry_point < sec_end {
                entry_in_last_section = true;
            }
        }

        sections_info.push(SectionInfo {
            name: name_str,
            virtual_size: sec.virtual_size,
            raw_size: sec.size_of_raw_data,
            entropy: sec_entropy,
            is_writable,
            is_executable,
            is_writable_and_executable: is_wx,
        });
    }

    if has_known_packer_name {
        score += 0.40;
        suspicious_reasons.push(DetectionReason::new(
            MatchSource::PeHeuristics,
            "Known Packer Section Name",
            "Executable contains section signatures typical of UPX, ASPack, or crypters",
            ThreatSeverity::Medium,
            0.40,
        ));
    }

    if has_high_entropy_section {
        score += 0.30;
        suspicious_reasons.push(DetectionReason::new(
            MatchSource::PeHeuristics,
            "High Section Entropy",
            format!("PE section exhibits Shannon entropy > 7.15 (overall: {:.2}), indicating compression or encryption", overall_entropy),
            ThreatSeverity::Medium,
            0.30,
        ));
    }

    if has_wx_section {
        score += 0.35;
        suspicious_reasons.push(DetectionReason::new(
            MatchSource::PeHeuristics,
            "Writable and Executable Section (W+X)",
            "Section is marked both Writable and Executable, characteristic of unpacking stubs and shellcode",
            ThreatSeverity::High,
            0.35,
        ));
    }

    if entry_in_last_section {
        score += 0.25;
        suspicious_reasons.push(DetectionReason::new(
            MatchSource::PeHeuristics,
            "Abnormal Entry Point",
            "Execution entry point resides in the final PE section, characteristic of appended malware loaders",
            ThreatSeverity::Medium,
            0.25,
        ));
    }

    // Parse and categorize imports
    let mut imported_functions = Vec::new();
    let mut imported_dlls = Vec::new();
    let mut import_set = HashSet::new();

    for import in &pe.imports {
        let dll_name = import.dll.to_lowercase();
        if !imported_dlls.contains(&dll_name) {
            imported_dlls.push(dll_name);
        }
        let fn_name = import.name.to_string().to_lowercase();
        import_set.insert(fn_name.clone());
        imported_functions.push(fn_name);
    }

    // Heuristics for suspicious import combinations
    let mut injection_hits = Vec::new();
    for &api in SUSPICIOUS_INJECTION_APIS {
        if import_set.contains(api) {
            injection_hits.push(api);
        }
    }
    if !injection_hits.is_empty() {
        let hit_count = injection_hits.len();
        let delta = (hit_count as f32 * 0.15).min(0.45);
        score += delta;
        suspicious_reasons.push(DetectionReason::new(
            MatchSource::PeHeuristics,
            "Process Injection APIs",
            format!("Executable imports process hollowing/injection APIs: {}", injection_hits.join(", ")),
            ThreatSeverity::High,
            delta,
        ));
    }

    let mut spyware_hits = Vec::new();
    for &api in SUSPICIOUS_SPYWARE_APIS {
        if import_set.contains(api) {
            spyware_hits.push(api);
        }
    }
    if !spyware_hits.is_empty() {
        score += 0.25;
        suspicious_reasons.push(DetectionReason::new(
            MatchSource::PeHeuristics,
            "Keylogging / Hooking APIs",
            format!("Executable imports keystroke monitoring or hook APIs: {}", spyware_hits.join(", ")),
            ThreatSeverity::Medium,
            0.25,
        ));
    }

    let mut evasion_hits = Vec::new();
    for &api in SUSPICIOUS_EVASION_APIS {
        if import_set.contains(api) {
            evasion_hits.push(api);
        }
    }
    if !evasion_hits.is_empty() {
        score += 0.15;
        suspicious_reasons.push(DetectionReason::new(
            MatchSource::PeHeuristics,
            "Anti-Analysis / Token Manipulation APIs",
            format!("Executable imports debugger check or privilege elevation APIs: {}", evasion_hits.join(", ")),
            ThreatSeverity::Low,
            0.15,
        ));
    }

    // Very low import count in a large binary is characteristic of packers/stubs
    if data.len() > 32 * 1024 && imported_functions.len() > 0 && imported_functions.len() < 5 {
        score += 0.20;
        suspicious_reasons.push(DetectionReason::new(
            MatchSource::PeHeuristics,
            "Low Import Count",
            format!("Binary is {} KB but only imports {} functions (typical of packed payloads)", data.len() / 1024, imported_functions.len()),
            ThreatSeverity::Low,
            0.20,
        ));
    }

    let clamped_score = score.min(1.0);
    debug!("PE heuristic analysis complete: score={:.2}, reasons={}", clamped_score, suspicious_reasons.len());

    Ok(PeAnalysis {
        is_valid_pe: true,
        is_64bit,
        overall_entropy,
        entry_point,
        sections: sections_info,
        imported_functions,
        imported_dlls,
        suspicious_reasons,
        heuristic_score: clamped_score,
    })
}
