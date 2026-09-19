//! High-level TrustedInstaller elevation checks and restart orchestrator.

use std::time::Duration;

use anyhow::Result;
use windows::core::{PCWSTR, w};

use crate::security::{
    Privilege, ProcessSpawner, ProcessToken, ServiceManager, TokenType, find_process_id_by_name,
};

/// TrustedInstaller Service Well-Known SID string (`NT SERVICE\TrustedInstaller`).
const TRUSTEDINSTALLER_SID_STRING: PCWSTR =
    w!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

/// The elevation status of the current process instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElevationStatus {
    /// The process is already running under TrustedInstaller privileges.
    TrustedInstaller,
    /// The process is running as a standard administrator and requires elevation.
    RequiresElevation,
}

/// Check whether the current process holds the TrustedInstaller SID in its token groups.
pub fn check_elevation_status() -> Result<ElevationStatus> {
    let current_token = ProcessToken::current_process()?;

    let is_elevated = current_token.contains_sid_string(TRUSTEDINSTALLER_SID_STRING)?;
    if is_elevated {
        Ok(ElevationStatus::TrustedInstaller)
    } else {
        Ok(ElevationStatus::RequiresElevation)
    }
}

/// Restart the current application under the TrustedInstaller identity in the active user session.
pub fn relaunch_as_trustedinstaller() -> Result<()> {
    // 1. Enable administrative debugging and impersonation privileges.
    ProcessToken::current_process()?
        .enable_privileges(&[Privilege::Debug, Privilege::Impersonate])?;

    // 2. Ensure TrustedInstaller service is running and fetch its PID.
    let trustedinstaller_process_id = ServiceManager::open()?
        .open_service(w!("TrustedInstaller"))?
        .start_and_wait(Duration::from_secs(30))?;

    // 3. Step into SYSTEM context via winlogon, then duplicate TrustedInstaller Primary Token.
    let primary_token = {
        let winlogon_process_id = find_process_id_by_name("winlogon.exe")?;
        let _impersonation_guard = ProcessToken::from_process_id(winlogon_process_id)?
            .duplicate(TokenType::Impersonation)?
            .impersonate()?;

        // While executing under SYSTEM identity, duplicate TrustedInstaller's primary token.
        ProcessToken::from_process_id(trustedinstaller_process_id)?.duplicate(TokenType::Primary)?
    };

    // 4. Spawn the elevated instance on the interactive desktop.
    ProcessSpawner::new_with_token(&primary_token)
        .current_exe()?
        .desktop("WinSta0\\Default")
        .spawn()?;

    Ok(())
}
