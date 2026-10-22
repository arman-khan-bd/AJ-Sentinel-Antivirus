use std::path::Path;
use tracing::debug;

use crate::models::{DetectionReason, MatchSource, ThreatSeverity};

pub struct ScriptAnalysis {
    pub is_script: bool,
    pub script_language: &'static str,
    pub suspicious_reasons: Vec<DetectionReason>,
    pub heuristic_score: f32,
}

pub fn is_script_extension(path: &Path) -> bool {
    if let Some(ext) = path.extension().and_then(|s| s.to_str()) {
        match ext.to_lowercase().as_str() {
            "ps1" | "psm1" | "psd1" | "vbs" | "vbe" | "js" | "jse" | "wsf" | "wsh" | "bat" | "cmd" | "hta" => true,
            _ => false,
        }
    } else {
        false
    }
}

pub fn analyze_script(content: &str, path: Option<&Path>) -> ScriptAnalysis {
    let mut reasons = Vec::new();
    let mut score = 0.0f32;

    let ext = path
        .and_then(|p| p.extension())
        .and_then(|e| e.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_default();

    let lang = match ext.as_str() {
        "ps1" | "psm1" | "psd1" => "PowerShell",
        "vbs" | "vbe" | "wsf" | "wsh" => "VBScript",
        "js" | "jse" => "JavaScript",
        "bat" | "cmd" => "Batch",
        "hta" => "HTA",
        _ => "UnknownScript",
    };

    let content_lower = content.to_lowercase();

    // 1. PowerShell Heuristics
    let has_ps_encoded = content_lower.contains("-enc ")
        || content_lower.contains("-encodedcommand")
        || content_lower.contains("frombase64string");

    let has_ps_download = content_lower.contains("net.webclient")
        || content_lower.contains("downloadstring")
        || content_lower.contains("downloadfile")
        || content_lower.contains("invoke-webrequest")
        || content_lower.contains("invokerestmethod")
        || content_lower.contains("curl ")
        || content_lower.contains("wget ");

    let has_ps_exec = content_lower.contains("invoke-expression")
        || content_lower.contains("iex ")
        || content_lower.contains("iex(")
        || content_lower.contains("[scriptblock]::create");

    let has_ps_amsi = content_lower.contains("amsiinitfailed")
        || content_lower.contains("amsiutils")
        || content_lower.contains("etweventwrite")
        || content_lower.contains("[ref].assembly.gettype");

    let has_ps_revshell = content_lower.contains("net.sockets.tcpclient");

    if has_ps_amsi {
        score += 0.50;
        reasons.push(DetectionReason::new(
            MatchSource::ScriptHeuristics,
            "PowerShell AMSI / Antivirus Bypass",
            "Script contains patterns designed to patch or disable the Antimalware Scan Interface (AMSI)",
            ThreatSeverity::Critical,
            0.50,
        ));
    }

    if has_ps_revshell {
        score += 0.60;
        reasons.push(DetectionReason::new(
            MatchSource::ScriptHeuristics,
            "PowerShell Reverse Shell",
            "Script establishes an interactive network TCP socket cradle typical of reverse shells",
            ThreatSeverity::Critical,
            0.60,
        ));
    }

    if has_ps_encoded && (has_ps_download || has_ps_exec) {
        score += 0.45;
        reasons.push(DetectionReason::new(
            MatchSource::ScriptHeuristics,
            "Obfuscated PowerShell Download Cradle",
            "Script combines Base64 encoding with WebClient/IEX execution cradles",
            ThreatSeverity::High,
            0.45,
        ));
    } else if has_ps_encoded {
        score += 0.25;
        reasons.push(DetectionReason::new(
            MatchSource::ScriptHeuristics,
            "Encoded PowerShell Command",
            "Script employs hidden Base64 command flags (-enc / FromBase64String)",
            ThreatSeverity::Medium,
            0.25,
        ));
    }

    // Check for backtick obfuscation: e.g. i`e`x or d`o`w`n`l`o`a`d
    let backtick_count = content.matches('`').count();
    if backtick_count > 15 {
        score += 0.30;
        reasons.push(DetectionReason::new(
            MatchSource::ScriptHeuristics,
            "Heavy Backtick Obfuscation",
            format!("Script contains {} backticks, characteristic of PowerShell keyword obfuscation", backtick_count),
            ThreatSeverity::Medium,
            0.30,
        ));
    }

    // 2. VBScript Heuristics
    let chr_count = content_lower.matches("chr(").count() + content_lower.matches("chrb(").count();
    if chr_count > 12 {
        score += 0.40;
        reasons.push(DetectionReason::new(
            MatchSource::ScriptHeuristics,
            "VBScript Character Concatenation Obfuscation",
            format!("Script contains {} Chr(...) calls used to conceal strings and payloads", chr_count),
            ThreatSeverity::High,
            0.40,
        ));
    }

    let has_vbs_shell = content_lower.contains("wscript.shell") || content_lower.contains("shell.application");
    let has_vbs_drop = content_lower.contains(".exe") && (content_lower.contains("temp") || content_lower.contains("appdata"));
    if has_vbs_shell && has_vbs_drop {
        score += 0.40;
        reasons.push(DetectionReason::new(
            MatchSource::ScriptHeuristics,
            "VBScript Dropper / Executable Spawner",
            "VBScript references WScript.Shell spawning an executable in Temp/AppData folders",
            ThreatSeverity::High,
            0.40,
        ));
    }

    // 3. JavaScript / JScript Heuristics
    let has_js_eval_unescape = content_lower.contains("eval(unescape(")
        || content_lower.contains("eval(decodeuricomponent(")
        || content_lower.contains("document.write(unescape(");
    if has_js_eval_unescape {
        score += 0.45;
        reasons.push(DetectionReason::new(
            MatchSource::ScriptHeuristics,
            "Obfuscated JavaScript Payload",
            "JavaScript uses eval(unescape(...)) to unpack hidden scripts dynamically",
            ThreatSeverity::High,
            0.45,
        ));
    }

    let has_js_activex = content_lower.contains("activexobject(\"wscript.shell\")")
        || content_lower.contains("activexobject('wscript.shell')");
    if has_js_activex {
        score += 0.35;
        reasons.push(DetectionReason::new(
            MatchSource::ScriptHeuristics,
            "Suspicious ActiveX Execution",
            "Script initializes ActiveX WScript.Shell to launch external system binaries",
            ThreatSeverity::Medium,
            0.35,
        ));
    }

    // 4. Batch file fork bomb or hidden PowerShell invocation
    if ext == "bat" || ext == "cmd" {
        if content_lower.contains("%0|%0") {
            score += 0.80;
            reasons.push(DetectionReason::new(
                MatchSource::ScriptHeuristics,
                "Batch Denial-of-Service (Fork Bomb)",
                "Batch file contains recursive %0|%0 execution loop designed to exhaust system resources",
                ThreatSeverity::Critical,
                0.80,
            ));
        }

        if content_lower.contains("-w hidden") || content_lower.contains("-windowstyle hidden") {
            score += 0.35;
            reasons.push(DetectionReason::new(
                MatchSource::ScriptHeuristics,
                "Batch Spawning Hidden Process",
                "Batch script instructs PowerShell to launch with hidden window style",
                ThreatSeverity::Medium,
                0.35,
            ));
        }
    }

    let clamped = score.min(1.0);
    debug!("Script heuristic analysis: score={:.2}, hits={}", clamped, reasons.len());

    ScriptAnalysis {
        is_script: true,
        script_language: lang,
        suspicious_reasons: reasons,
        heuristic_score: clamped,
    }
}
