//! Typed error variants for TrustedInstaller elevation operations.
//!
//! Provides the [`ElevateError`] enum that encapsulates all failure modes
//! encountered across process, token, service, and elevation subsystems.

use std::{error::Error, fmt};

/// The outcome error type for TrustedInstaller elevation operations.
///
/// Distinguishes between Win32 subsystem failures, privilege adjustments,
/// missing target processes, and service wait timeouts.
#[derive(Debug)]
pub enum ElevateError {
    /// A Win32 API call returned an error code.
    Win32 {
        /// The operation description where the error occurred.
        operation: &'static str,
        /// The raw Windows error returned by the subsystem.
        source: windows::core::Error,
    },
    /// Privilege adjustment was only partially assigned or rejected.
    PrivilegeNotAssigned {
        /// The specific privilege name that failed to be assigned.
        privilege_name: &'static str,
        /// The Win32 error code returned.
        error_code: u32,
    },
    /// A required genuine Windows SYSTEM process could not be located.
    SystemProcessNotFound {
        /// The name of the process being searched.
        process_name: String,
    },
    /// Waiting for a service to reach the running state timed out.
    ServiceWaitTimeout {
        /// Name of the service that timed out.
        service_name: String,
        /// The duration waited before timing out.
        elapsed_seconds: u64,
    },
    /// The target binary executable path could not be resolved.
    ExecutablePathUnavailable {
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// The current working directory could not be resolved.
    CurrentDirectoryUnavailable {
        /// The underlying I/O error.
        source: std::io::Error,
    },
    /// Target executable path was not specified prior to spawning.
    ExecutablePathMissing,
    /// Token information buffer query returned a zero size.
    TokenInformationBufferEmpty {
        /// Description of the token information queried.
        information_class: &'static str,
    },
    /// A wide-character or binary SID buffer failed UTF-8 string conversion.
    SidStringConversionFailed,
}

impl fmt::Display for ElevateError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Win32 { operation, source } => {
                write!(
                    formatter,
                    "Win32 operation '{operation}' failed with error 0x{:08X}: {source}",
                    source.code().0
                )
            }
            Self::PrivilegeNotAssigned {
                privilege_name,
                error_code,
            } => {
                write!(
                    formatter,
                    "Privilege '{privilege_name}' could not be assigned (Win32 error: 0x{error_code:08X})"
                )
            }
            Self::SystemProcessNotFound { process_name } => {
                write!(
                    formatter,
                    "Genuine SYSTEM process '{process_name}' could not be found"
                )
            }
            Self::ServiceWaitTimeout {
                service_name,
                elapsed_seconds,
            } => {
                write!(
                    formatter,
                    "Timed out waiting for service '{service_name}' after {elapsed_seconds} seconds"
                )
            }
            Self::ExecutablePathUnavailable { source } => {
                write!(
                    formatter,
                    "Failed to resolve current binary executable path: {source}"
                )
            }
            Self::CurrentDirectoryUnavailable { source } => {
                write!(
                    formatter,
                    "Failed to resolve current working directory: {source}"
                )
            }
            Self::ExecutablePathMissing => {
                write!(
                    formatter,
                    "Executable path must be specified before launching process"
                )
            }
            Self::TokenInformationBufferEmpty { information_class } => {
                write!(
                    formatter,
                    "Token query returned zero size for '{information_class}'"
                )
            }
            Self::SidStringConversionFailed => {
                write!(formatter, "Failed to parse SID string buffer as UTF-8")
            }
        }
    }
}

impl Error for ElevateError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Win32 { source, .. } => Some(source),
            Self::ExecutablePathUnavailable { source }
            | Self::CurrentDirectoryUnavailable { source } => Some(source),
            _ => None,
        }
    }
}
