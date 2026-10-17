//! A safe, idiomatic Rust library to obtain Windows `TrustedInstaller` privileges.

pub mod error;
pub mod security;
pub mod strategy;

pub use error::ElevateError;
pub use security::{ImpersonationGuard, Privilege, Sid, Token, TokenCommand, TokenType};
pub use strategy::ElevationStrategy;
