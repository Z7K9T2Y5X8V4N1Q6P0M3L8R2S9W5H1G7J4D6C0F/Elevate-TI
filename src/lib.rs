//! A safe, idiomatic Rust library for obtaining Windows TrustedInstaller privileges.

mod elevation;
pub mod error;
pub mod security;

pub use elevation::{ElevationStatus, check_elevation_status, relaunch_as_trustedinstaller};
pub use error::ElevateError;
pub use security::{Privilege, ProcessSpawner, ProcessToken, Sid, TokenType};
