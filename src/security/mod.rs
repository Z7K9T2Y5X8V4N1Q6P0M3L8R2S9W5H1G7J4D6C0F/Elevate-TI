//! Idiomatic, safe Win32 security and process primitives.
//!
//! # Module Structure
//! - [`macros`]   — internal helper macros for concise Win32 API calls
//! - [`process`]  — process discovery and token-based spawning utilities
//! - [`service`]  — Service Control Manager connection and service polling
//! - [`sid`]      — strongly typed Windows Security Identifier (SID) wrapper
//! - [`token`]    — process/thread security token manipulation and privilege elevation

pub(crate) mod macros;
pub mod process;
pub mod service;
pub mod sid;
pub mod token;

pub use process::{ProcessSpawner, find_process_id_by_name};
pub use service::ServiceManager;
pub use sid::Sid;
pub use token::{Privilege, ProcessToken, TokenType};
