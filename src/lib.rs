//! A safe, idiomatic Rust library for obtaining Windows TrustedInstaller privileges.
//!
//! # Usage
//! ```no_run
//! use elevate_ti::{check_elevation_status, relaunch_as_trustedinstaller, ElevationStatus};
//!
//! if check_elevation_status().unwrap() == ElevationStatus::RequiresElevation {
//!     relaunch_as_trustedinstaller().unwrap();
//!     return;
//! }
//! ```

mod elevation;
pub mod error;
pub mod security;

pub use elevation::{ElevationStatus, check_elevation_status, relaunch_as_trustedinstaller};
pub use error::ElevateError;
pub use security::{Privilege, ProcessSpawner, ProcessToken, TokenType};
