use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use rayon::prelude::*;
use walkdir::WalkDir;

use core_engine::{
    analyze_pe, analyze_script, calculate_entropy,
    verify_authenticode, DatabaseManager, DetectionEngine, EngineConfig, ScanResult, Verdict,
    YaraEngine,
};

// ANSI terminal color codes
const RESET: &str = "\x1b[0m";
const BOLD: &str = "\x1b[1m";
const RED: &str = "\x1b[1;31m";
const GREEN: &str = "\x1b[1;32m";
const YELLOW: &str = "\x1b[1;33m";
const CYAN: &str = "\x1b[1;36m";
const GRAY: &str = "\x1b[90m";

fn print_banner() {
    println!("{CYAN}{BOLD}");
    println!(r#"  ____  _     _      _     _  ____                     _ "#);
    println!(r#" / ___|| |__ (_) ___| | __| |/ ___|_   _  __ _ _ __ __| |"#);
    println!(r#" \___ \| '_ \| |/ _ \ |/ _` | |  _| | | |/ _` | '__/ _` |"#);
    println!(r#"  ___) | | | | |  __/ | (_| | |_| | |_| | (_| | | | (_| |"#);
    println!(r#" |____/|_| |_|_|\___|_|\__,_|\____|\__,_|\__,_|_|  \__,_|"#);
    println!(r#"                                                         "#);
    println!(" ShieldGuard Defensive Antivirus Engine v0.1.0{RESET}");
    println!("{GRAY} Next-Gen Windows Threat Detection & Prevention System{RESET}\n");
}

fn print_usage() {
    println!("{BOLD}Usage:{RESET}");
    println!("  shieldguard-cli scan <file_or_directory_path>");
    println!("  shieldguard-cli eicar");
    println!("  shieldguard-cli import-hashes <csv_file>");
    println!("  shieldguard-cli rules-info");
    println!("  shieldguard-cli heuristics-demo <file_path>");
    println!("  shieldguard-cli db-init");
    println!("\n{BOLD}Examples:{RESET}");
    println!("  shieldguard-cli scan C:\\Windows\\System32\\calc.exe");
    println!("  shieldguard-cli scan C:\\Users\\User\\Downloads");
    println!("  shieldguard-cli eicar");
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = env::args().collect();
    print_banner();

    if args.len() < 2 {
        print_usage();
        return Ok(());
    }

    let command = args[1].to_lowercase();
    match command.as_str() {
        "scan" => {
            if args.len() < 3 {
                eprintln!("{RED}Error: Please specify a file or folder path to scan.{RESET}");
                println!("Example: shieldguard-cli scan C:\\Windows\\notepad.exe");
                return Ok(());
            }
            let target_path = PathBuf::from(&args[2]);
            run_scan_command(&target_path)?;
        }
        "eicar" => {
            run_eicar_test()?;
        }
        "import-hashes" => {
            if args.len() < 3 {
                eprintln!("{RED}Error: Please specify the MalwareBazaar CSV file path.{RESET}");
                return Ok(());
            }
            let csv_path = PathBuf::from(&args[2]);
            run_import_hashes(&csv_path)?;
        }
        "rules-info" => {
            run_rules_info()?;
        }
        "heuristics-demo" => {
            if args.len() < 3 {
                eprintln!("{RED}Error: Please specify a PE executable or script to analyze.{RESET}");
                return Ok(());
            }
            let target = PathBuf::from(&args[2]);
            run_heuristics_demo(&target)?;
        }
        "db-init" => {
            run_db_init()?;
        }
        "help" | "-h" | "--help" => {
            print_usage();
        }
        _ => {
            eprintln!("{RED}Unknown command: {}{RESET}", command);
            print_usage();
        }
    }

    Ok(())
}

fn init_engine() -> anyhow::Result<DetectionEngine> {
    let db_path = "shieldguard.db";
    let db = DatabaseManager::open(db_path)?;
    let rules_path = Path::new("rules");
    let yara = if rules_path.exists() {
        YaraEngine::load_from_dir(rules_path)?
    } else {
        YaraEngine::new()?
    };
    let config = EngineConfig::default();
    let engine = DetectionEngine::new(db, yara, config)?;
    Ok(engine)
}

fn run_scan_command(path: &Path) -> anyhow::Result<()> {
    if !path.exists() {
        eprintln!("{RED}Error: Target path does not exist: {:?}{RESET}", path);
        return Ok(());
    }

    let engine = Arc::new(init_engine()?);
    let start_instant = Instant::now();

    if path.is_file() {
        println!("{BOLD}Scanning single file:{RESET} {:?}", path);
        let result = engine.scan_file(path)?;
        print_scan_result(&result);
    } else if path.is_dir() {
        println!("{BOLD}Starting directory scan:{RESET} {:?}\n", path);

        let mut files_to_scan = Vec::new();
        for entry in WalkDir::new(path).into_iter().filter_map(|e| e.ok()) {
            if entry.file_type().is_file() {
                files_to_scan.push(entry.into_path());
            }
        }

        let total_files = files_to_scan.len();
        println!("{CYAN}Found {} files to scan using Rayon multi-threading...{RESET}\n", total_files);

        let clean_count = AtomicUsize::new(0);
        let suspicious_count = AtomicUsize::new(0);
        let malicious_count = AtomicUsize::new(0);

        files_to_scan.par_iter().for_each(|file_path| {
            if let Ok(res) = engine.scan_file(file_path) {
                match res.verdict {
                    Verdict::Clean => {
                        clean_count.fetch_add(1, Ordering::Relaxed);
                    }
                    Verdict::Suspicious => {
                        suspicious_count.fetch_add(1, Ordering::Relaxed);
                        println!("{YELLOW}[SUSPICIOUS]{RESET} {:?} ({:.0}% confidence)", file_path, res.confidence * 100.0);
                        if let Some(name) = &res.threat_name {
                            println!("  Threat: {YELLOW}{}{RESET}", name);
                        }
                    }
                    Verdict::Malicious => {
                        malicious_count.fetch_add(1, Ordering::Relaxed);
                        println!("{RED}[MALICIOUS]{RESET} {:?} ({:.0}% confidence)", file_path, res.confidence * 100.0);
                        if let Some(name) = &res.threat_name {
                            println!("  Threat: {RED}{}{RESET}", name);
                        }
                    }
                }
            }
        });

        let elapsed = start_instant.elapsed();
        let total_clean = clean_count.load(Ordering::SeqCst);
        let total_suspicious = suspicious_count.load(Ordering::SeqCst);
        let total_malicious = malicious_count.load(Ordering::SeqCst);

        println!("\n{CYAN}================ SCAN SUMMARY ================{RESET}");
        println!("  Target:             {:?}", path);
        println!("  Files Scanned:      {}", total_files);
        println!("  Clean Files:        {GREEN}{}{RESET}", total_clean);
        println!("  Suspicious Files:   {YELLOW}{}{RESET}", total_suspicious);
        println!("  Malicious Threats:  {RED}{}{RESET}", total_malicious);
        println!("  Elapsed Time:       {:.2}s ({:.1} files/sec)", elapsed.as_secs_f64(), total_files as f64 / elapsed.as_secs_f64().max(0.001));
        println!("{CYAN}=============================================={RESET}");
    }

    Ok(())
}

fn print_scan_result(res: &ScanResult) {
    println!("\n{CYAN}================ FILE SCAN RESULT ================{RESET}");
    println!("  File Path:      {:?}", res.path);
    println!("  File Size:      {} bytes ({:.2} KB)", res.file_size, res.file_size as f64 / 1024.0);
    println!("  File Type:      {}", res.file_type);
    println!("  Entropy:        {:.2} / 8.00", res.entropy);
    println!("  SHA-256:        {}", res.hashes.sha256);
    println!("  BLAKE3:         {}", res.hashes.blake3);

    if res.is_pe {
        println!("  Authenticode:   {}", if res.authenticode_verified {
            format!("{GREEN}Valid Digital Signature ({:?}){RESET}", res.authenticode_subject.as_deref().unwrap_or("Trusted"))
        } else {
            format!("{YELLOW}Unsigned / Unverified{RESET}")
        });
    }

    let verdict_str = match res.verdict {
        Verdict::Clean => format!("{GREEN}[ CLEAN ]{RESET}"),
        Verdict::Suspicious => format!("{YELLOW}[ SUSPICIOUS ]{RESET}"),
        Verdict::Malicious => format!("{RED}[ MALICIOUS THREAT DETECTED ]{RESET}"),
    };

    println!("\n  Verdict:        {}", verdict_str);
    println!("  Confidence:     {:.1}%", res.confidence * 100.0);
    if let Some(threat) = &res.threat_name {
        println!("  Threat Name:    {BOLD}{}{RESET}", threat);
    }
    if let Some(cat) = &res.threat_category {
        println!("  Category:       {:?}", cat);
    }

    if !res.detection_reasons.is_empty() {
        println!("\n  {BOLD}Detection Indicators ({}) :{RESET}", res.detection_reasons.len());
        for (i, r) in res.detection_reasons.iter().enumerate() {
            println!("    {}. [{:?}] {}: {}", i + 1, r.source, r.title, r.details);
        }
    }

    println!("  Scan Duration:  {} ms", res.scan_duration_ms);
    println!("{CYAN}=================================================={RESET}\n");
}

fn run_eicar_test() -> anyhow::Result<()> {
    println!("{BOLD}Running EICAR Standard Antivirus Test Verification...{RESET}\n");
    let eicar_bytes = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*";

    let engine = init_engine()?;
    let result = engine.scan_bytes(eicar_bytes, Some("EICAR_Standard_Test_File.com"));

    print_scan_result(&result);

    if result.verdict == Verdict::Malicious && result.confidence == 1.0 {
        println!("{GREEN}[PASS] EICAR Standard Antivirus detection successfully verified!{RESET}");
        println!("ShieldGuard core engine correctly identified the test payload with 100% confidence.\n");
    } else {
        println!("{RED}[FAIL] EICAR detection did not achieve expected verdict.{RESET}\n");
    }

    Ok(())
}

fn run_import_hashes(path: &Path) -> anyhow::Result<()> {
    println!("{BOLD}Importing MalwareBazaar hashes from:{RESET} {:?}", path);
    let db = DatabaseManager::open("shieldguard.db")?;
    let start = Instant::now();
    let count = db.import_malware_bazaar_csv(path)?;
    let elapsed = start.elapsed();
    println!("{GREEN}Successfully imported {} malware hashes in {:.2}s!{RESET}\n", count, elapsed.as_secs_f64());
    Ok(())
}

fn run_rules_info() -> anyhow::Result<()> {
    println!("{BOLD}Loaded YARA Detection Rules:{RESET}");
    let yara = YaraEngine::new()?;
    println!("  ✓ Built-in EICAR Standard Test File Rule");
    println!("  ✓ Built-in Obfuscated PowerShell Download Cradle Rule");
    println!("  ✓ Built-in PHP Webshell & Backdoor Rule");
    println!("  ✓ Built-in Ransomware Note Pattern Rule");
    println!("  ✓ Built-in Mimikatz Credential Dumper Rule");

    let custom_rules = Path::new("rules");
    if custom_rules.exists() {
        println!("\n  Scanning custom rules directory: {:?}", custom_rules);
        let reloaded = yara.hot_reload(custom_rules)?;
        println!("  ✓ Hot-reloaded {} custom rule files", reloaded);
    } else {
        println!("\n  Directory 'rules/' does not exist yet. Using embedded baseline rules.");
    }
    println!();
    Ok(())
}

fn run_heuristics_demo(path: &Path) -> anyhow::Result<()> {
    println!("{BOLD}Deep Heuristics Inspection for:{RESET} {:?}\n", path);
    let bytes = fs::read(path)?;
    let entropy = calculate_entropy(&bytes);
    println!("  File Size: {} bytes", bytes.len());
    println!("  Shannon Entropy: {:.3} / 8.00", entropy);

    if bytes.starts_with(b"MZ") {
        println!("\n{CYAN}--- PE Executable Heuristics ---{RESET}");
        let auth = verify_authenticode(path);
        println!("  Digital Signature: Signed={}, Valid={}, Trusted={}", auth.is_signed, auth.is_valid, auth.is_trusted_publisher);
        if let Some(pub_name) = auth.publisher_name {
            println!("  Publisher: {}", pub_name);
        }

        match analyze_pe(&bytes) {
            Ok(pe) => {
                println!("  Architecture: {}", if pe.is_64bit { "64-bit (x64)" } else { "32-bit (x86)" });
                println!("  Entry Point: 0x{:X}", pe.entry_point);
                println!("  Imported DLLs ({}): {}", pe.imported_dlls.len(), pe.imported_dlls.join(", "));
                println!("  Total Imported Functions: {}", pe.imported_functions.len());
                println!("  Sections ({}):", pe.sections.len());
                for s in &pe.sections {
                    println!("    • {:<10} Raw: {:<8} Entropy: {:.2}  Executable: {:<5} Writable: {:<5} W+X: {}",
                        s.name, s.raw_size, s.entropy, s.is_executable, s.is_writable, s.is_writable_and_executable
                    );
                }
                println!("\n  Heuristic Risk Score: {:.2} / 1.00", pe.heuristic_score);
                if !pe.suspicious_reasons.is_empty() {
                    println!("  Flagged Heuristics:");
                    for r in &pe.suspicious_reasons {
                        println!("    • [{:?}] {}: {}", r.severity, r.title, r.details);
                    }
                }
            }
            Err(e) => println!("  {RED}PE parse error: {}{RESET}", e),
        }
    } else {
        println!("\n{CYAN}--- Script Heuristics ---{RESET}");
        let text = String::from_utf8_lossy(&bytes);
        let script_res = analyze_script(&text, Some(path));
        println!("  Detected Language: {}", script_res.script_language);
        println!("  Heuristic Risk Score: {:.2} / 1.00", script_res.heuristic_score);
        if !script_res.suspicious_reasons.is_empty() {
            println!("  Flagged Heuristics:");
            for r in &script_res.suspicious_reasons {
                println!("    • [{:?}] {}: {}", r.severity, r.title, r.details);
            }
        }
    }
    println!();
    Ok(())
}

fn run_db_init() -> anyhow::Result<()> {
    let db_path = "shieldguard.db";
    println!("{BOLD}Initializing ShieldGuard database at:{RESET} {}", db_path);
    let db = DatabaseManager::open(db_path)?;
    let settings = db.get_all_settings()?;
    println!("{GREEN}✓ Database initialized successfully!{RESET}");
    println!("Default configurations loaded:");
    for (k, v) in settings {
        println!("  • {:<25} = {}", k, v);
    }
    println!();
    Ok(())
}
