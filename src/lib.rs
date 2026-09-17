//! A safe, idiomatic Rust library for obtaining Windows TrustedInstaller privileges.
//!
//! # Usage
//! ```no_run
//! use elevate_ti::{check_elevation_status, relaunch_as_trusted_installer, ElevationStatus};
//!
//! if check_elevation_status().unwrap() == ElevationStatus::RequiresElevation {
//!     relaunch_as_trusted_installer().unwrap();
//!     return;
//! }
//! ```

pub mod primitives;
mod relaunch;

pub use primitives::{Privilege, ProcessSpawner, ProcessToken, TokenType};
pub use relaunch::{ElevationStatus, check_elevation_status, relaunch_as_trusted_installer};
