// Example custom YARA detection rule for ShieldGuard
rule Suspicious_Macro_Downloader {
    meta:
        description = "Detects VBA macro download cradles in Office documents"
        threat_name = "Trojan.Downloader.VBA"
        severity = "high"
        category = "dropper"
    strings:
        $vba1 = "AutoOpen" nocase
        $vba2 = "Document_Open" nocase
        $url1 = "URLDownloadToFile" nocase
        $url2 = "MSXML2.ServerXMLHTTP" nocase
        $url3 = "WinHttp.WinHttpRequest" nocase
    condition:
        ($vba1 or $vba2) and ($url1 or $url2 or $url3)
}
