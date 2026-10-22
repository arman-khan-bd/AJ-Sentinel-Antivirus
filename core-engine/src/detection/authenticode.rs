use std::path::Path;
use tracing::debug;

pub const TRUSTED_PUBLISHERS: &[&str] = &[
    "Microsoft Corporation",
    "Microsoft Windows",
    "Microsoft Windows Publisher",
    "Google LLC",
    "Mozilla Corporation",
    "Valve Corp.",
    "Adobe Inc.",
    "Apple Inc.",
    "Oracle America, Inc.",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticodeResult {
    pub is_signed: bool,
    pub is_valid: bool,
    pub is_trusted_publisher: bool,
    pub publisher_name: Option<String>,
    pub status_message: String,
}

impl AuthenticodeResult {
    pub fn unsigned() -> Self {
        Self {
            is_signed: false,
            is_valid: false,
            is_trusted_publisher: false,
            publisher_name: None,
            status_message: "File is not digitally signed".to_string(),
        }
    }

    pub fn is_trusted(&self) -> bool {
        self.is_signed && self.is_valid && self.is_trusted_publisher
    }
}

/// Checks Authenticode digital signature on Windows using WinVerifyTrust
#[cfg(windows)]
pub fn verify_authenticode(path: &Path) -> AuthenticodeResult {
    use std::os::windows::ffi::OsStrExt;
    use windows::core::GUID;
    use windows::Win32::Foundation::HWND;
    use windows::Win32::Security::WinTrust::{
        WinVerifyTrust, WINTRUST_DATA, WINTRUST_DATA_0, WINTRUST_DATA_PROVIDER_FLAGS,
        WINTRUST_DATA_UICONTEXT, WINTRUST_FILE_INFO, WTD_CHOICE_FILE, WTD_REVOKE_NONE,
        WTD_STATEACTION_IGNORE, WTD_UI_NONE,
    };

    // WINTRUST_ACTION_GENERIC_VERIFY_V2: {00AAC56B-CD44-11d0-8CC2-00C04FC295EE}
    let mut action_guid: GUID = GUID::from_u128(0x00aac56b_cd44_11d0_8cc2_00c04fc295ee);

    let wide_path: Vec<u16> = path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();

    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: windows::core::PCWSTR::from_raw(wide_path.as_ptr()),
        hFile: windows::Win32::Foundation::HANDLE::default(),
        pgKnownSubject: std::ptr::null_mut(),
    };

    let mut trust_data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        pPolicyCallbackData: std::ptr::null_mut(),
        pSIPClientData: std::ptr::null_mut(),
        dwUIChoice: WTD_UI_NONE,
        fdwRevocationChecks: WTD_REVOKE_NONE,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info as *mut _,
        },
        dwStateAction: WTD_STATEACTION_IGNORE,
        hWVTStateData: windows::Win32::Foundation::HANDLE::default(),
        pwszURLReference: windows::core::PWSTR::null(),
        dwProvFlags: WINTRUST_DATA_PROVIDER_FLAGS(0x00000010 | 0x00000080), // WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL
        dwUIContext: WINTRUST_DATA_UICONTEXT(0),
        pSignatureSettings: std::ptr::null_mut(),
    };

    // Call WinVerifyTrust safely
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action_guid as *mut GUID,
            &mut trust_data as *mut _ as *mut std::ffi::c_void,
        )
    };

    debug!("WinVerifyTrust status for {:?}: {:#x}", path, status);

    if status == 0 {
        // Valid digital signature trusted by Windows root CA
        AuthenticodeResult {
            is_signed: true,
            is_valid: true,
            is_trusted_publisher: true,
            publisher_name: Some("Verified Windows CA Publisher".to_string()),
            status_message: "Valid digital signature verified by Windows Trust Provider".to_string(),
        }
    } else {
        let is_signed = status != -2146762496i32; // 0x800B0100 (TRUST_E_NOSIGNATURE)
        let msg = match status {
            -2146762496 => "Unsigned binary".to_string(),
            -2146869232 => "Signature hash mismatch (tampered file)".to_string(),
            -2146762479 => "Explicitly untrusted certificate".to_string(),
            _ => format!("Signature verification failed with status {:#x}", status),
        };

        AuthenticodeResult {
            is_signed,
            is_valid: false,
            is_trusted_publisher: false,
            publisher_name: None,
            status_message: msg,
        }
    }
}

/// Fallback for non-Windows platforms
#[cfg(not(windows))]
pub fn verify_authenticode(_path: &Path) -> AuthenticodeResult {
    AuthenticodeResult::unsigned()
}

pub fn is_trusted_publisher_name(name: &str) -> bool {
    let name_lower = name.to_lowercase();
    TRUSTED_PUBLISHERS
        .iter()
        .any(|trusted| name_lower.contains(&trusted.to_lowercase()))
}
