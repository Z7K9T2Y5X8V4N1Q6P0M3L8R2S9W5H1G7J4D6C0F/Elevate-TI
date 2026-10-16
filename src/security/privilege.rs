//! Administrative security privilege definitions.

use windows::core::{PCWSTR, w};

/// Administrative Windows security privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// Debug programs (`SeDebugPrivilege`).
    Debug,
    /// Impersonate a client after authentication (`SeImpersonatePrivilege`).
    Impersonate,
}

impl Privilege {
    pub(crate) const fn as_pcwstr(self) -> PCWSTR {
        match self {
            Self::Debug => w!("SeDebugPrivilege"),
            Self::Impersonate => w!("SeImpersonatePrivilege"),
        }
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Debug => "SeDebugPrivilege",
            Self::Impersonate => "SeImpersonatePrivilege",
        }
    }
}
