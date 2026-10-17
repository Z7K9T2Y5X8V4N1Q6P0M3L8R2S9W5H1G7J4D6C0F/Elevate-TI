//! Classic Winlogon (SYSTEM) -> `TrustedInstaller` chained elevation strategy.

use std::time::Duration;
use windows::core::w;

use crate::{
    error::ElevateError,
    security::{Privilege, ProcessSnapshot, ServiceManager, Token, TokenType},
    strategy::ElevationStrategy,
};

/// Local System Account Well-Known SID string (`NT AUTHORITY\SYSTEM`).
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// Chained elevation strategy utilizing winlogon to impersonate SYSTEM, then capturing `TrustedInstaller`.
pub struct TrustedInstallerStrategy {
    service_timeout: Duration,
}

impl Default for TrustedInstallerStrategy {
    fn default() -> Self {
        Self {
            service_timeout: Duration::from_secs(30),
        }
    }
}

impl TrustedInstallerStrategy {
    /// Create a strategy instance with a custom service start wait timeout.
    pub const fn with_timeout(service_timeout: Duration) -> Self {
        Self { service_timeout }
    }
}

impl ElevationStrategy for TrustedInstallerStrategy {
    fn acquire_primary_token(&self) -> Result<Token, ElevateError> {
        // 1. Enable administrative debug and impersonation privileges on current token.
        let cur_token = Token::current()?;
        cur_token.enable_privileges(&[Privilege::Debug, Privilege::Impersonate])?;
        let caller_session_id = cur_token.session_id()?;

        // 2. Ensure TrustedInstaller service is running and query its process ID.
        let ti_pid = ServiceManager::open()?
            .service(w!("TrustedInstaller"))?
            .start_and_wait("TrustedInstaller", self.service_timeout)?;

        // 3. Locate the genuine SYSTEM winlogon process running in current session.
        let winlogon_pid = find_system_process("winlogon.exe", caller_session_id)?;

        // 4. Temporarily impersonate winlogon to execute under genuine SYSTEM context.
        let _impersonation_guard = Token::from_pid(winlogon_pid)?
            .duplicate(TokenType::Impersonation)?
            .impersonate()?;

        // 5. While running as SYSTEM, duplicate the TrustedInstaller primary token.
        let ti_primary_token = Token::from_pid(ti_pid)?.duplicate(TokenType::Primary)?;

        // 6. Breakthrough Session 0 isolation: explicitly assign caller's interactive session ID.
        ti_primary_token.set_session_id(caller_session_id)?;

        Ok(ti_primary_token)
    }
}

/// Find a genuine SYSTEM process ID by name inside the specified session.
fn find_system_process(process_name: &str, session_id: u32) -> Result<u32, ElevateError> {
    for (pid, name) in ProcessSnapshot::new()? {
        if !name.eq_ignore_ascii_case(process_name) {
            continue;
        }

        if let Ok(token) = Token::from_pid(pid) {
            let is_matching_session = token.session_id().is_ok_and(|s| s == session_id);
            let is_system_user = token.user_sid().is_ok_and(|sid| sid == LOCAL_SYSTEM_SID);

            if is_matching_session && is_system_user {
                return Ok(pid);
            }
        }
    }

    Err(ElevateError::ProcessNotFound(process_name.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strategy_default_timeout() {
        let strategy = TrustedInstallerStrategy::default();
        assert_eq!(strategy.service_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_strategy_custom_timeout() {
        let strategy = TrustedInstallerStrategy::with_timeout(Duration::from_secs(10));
        assert_eq!(strategy.service_timeout, Duration::from_secs(10));
    }
}
