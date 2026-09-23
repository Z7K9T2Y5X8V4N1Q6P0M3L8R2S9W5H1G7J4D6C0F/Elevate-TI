//! Typed error variants for TrustedInstaller elevation operations.
//!
//! Provides the [`ElevateError`] enum that encapsulates all failure modes
//! encountered across process, token, service, and elevation subsystems.

use std::io;

use thiserror::Error;

/// The outcome error type for TrustedInstaller elevation operations.
///
/// Distinguishes between Win32 subsystem failures, privilege adjustments,
/// missing target processes, and service wait timeouts.
#[derive(Debug, Error)]
pub enum ElevateError {
    /// A Win32 API call returned an error code.
    #[error("Win32 operation '{operation}' failed with error 0x{:08X}: {source}", source.code().0)]
    Win32 {
        /// The operation description where the error occurred.
        operation: &'static str,
        /// The raw Windows error returned by the subsystem.
        #[source]
        source: windows::core::Error,
    },

    /// Privilege adjustment was only partially assigned or rejected.
    #[error("Privilege '{privilege_name}' could not be assigned (Win32 error: 0x{error_code:08X})")]
    PrivilegeNotAssigned {
        /// The specific privilege name that failed to be assigned.
        privilege_name: &'static str,
        /// The Win32 error code returned.
        error_code: u32,
    },

    /// A required genuine Windows SYSTEM process could not be located.
    #[error("Genuine SYSTEM process '{process_name}' could not be found in active session")]
    SystemProcessNotFound {
        /// The name of the process being searched.
        process_name: String,
    },

    /// Waiting for a service to reach the running state timed out.
    #[error("Timed out waiting for service '{service_name}' after {elapsed_seconds} seconds")]
    ServiceWaitTimeout {
        /// Name of the service that timed out.
        service_name: String,
        /// The duration waited before timing out.
        elapsed_seconds: u64,
    },

    /// An environment I/O path or directory could not be resolved.
    #[error("System I/O query failed: {source}")]
    IoError {
        /// The underlying I/O error.
        #[from]
        source: io::Error,
    },

    /// Target executable path was not specified prior to spawning.
    #[error("Executable path must be specified before launching process")]
    ExecutablePathMissing,

    /// Token information buffer query returned a zero size.
    #[error("Token query returned zero size for '{information_class}'")]
    TokenInformationBufferEmpty {
        /// Description of the token information queried.
        information_class: &'static str,
    },

    /// A wide-character or binary SID buffer failed UTF-8 string conversion.
    #[error("Failed to parse SID string buffer as UTF-8")]
    SidStringConversionFailed,
}
