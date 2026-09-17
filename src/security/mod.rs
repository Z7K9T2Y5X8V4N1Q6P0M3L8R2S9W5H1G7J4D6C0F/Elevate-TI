//! Idiomatic, safe Win32 security and process primitives.

pub mod process;
pub mod service;
pub mod sid;
pub mod token;

pub use process::{ProcessSpawner, find_process_id_by_name};
pub use service::ServiceManager;
pub use sid::Sid;
pub use token::{Privilege, ProcessToken, TokenType};
