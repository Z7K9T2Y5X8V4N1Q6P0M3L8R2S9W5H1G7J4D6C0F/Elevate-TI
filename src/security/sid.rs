//! Strongly-typed Windows Security Identifier (SID) wrapper.
//!
//! Encapsulates raw Win32 `PSID` allocation and provides safe RAII
//! deallocation via [`windows::Win32::Foundation::LocalFree`].

use windows::{
    Win32::{
        Foundation::{HLOCAL, LocalFree},
        Security::{
            Authorization::{ConvertSidToStringSidW, ConvertStringSidToSidW},
            PSID,
        },
    },
    core::{PCWSTR, PWSTR},
};

use crate::error::ElevateError;

/// Strongly-typed RAII wrapper for a Windows Security Identifier (SID).
pub struct Sid {
    raw_sid: PSID,
}

impl Drop for Sid {
    fn drop(&mut self) {
        if !self.raw_sid.is_invalid() {
            unsafe {
                let _ = LocalFree(HLOCAL(self.raw_sid.0));
            }
        }
    }
}

/// RAII guard releasing a [`PWSTR`] buffer allocated by Win32 functions via [`LocalFree`].
struct LocalAllocatedStringGuard {
    pointer: PWSTR,
}

impl Drop for LocalAllocatedStringGuard {
    fn drop(&mut self) {
        if !self.pointer.is_null() {
            unsafe {
                let _ = LocalFree(HLOCAL(self.pointer.0.cast()));
            }
        }
    }
}

impl Sid {
    /// Parse a security identifier from a wide string constant.
    pub fn parse(sid_string: PCWSTR) -> Result<Self, ElevateError> {
        let mut raw_sid = PSID::default();
        unsafe { ConvertStringSidToSidW(sid_string, &mut raw_sid) }.map_err(|source| {
            ElevateError::Win32 {
                operation: "ConvertStringSidToSidW",
                source,
            }
        })?;

        Ok(Self { raw_sid })
    }

    /// Retrieve the underlying raw `PSID`.
    pub const fn raw(&self) -> PSID {
        self.raw_sid
    }

    /// Convert a raw `PSID` into its standard string representation.
    pub fn to_string_from_raw(raw_sid: PSID) -> Result<String, ElevateError> {
        let mut sid_pwstr = PWSTR::null();
        unsafe { ConvertSidToStringSidW(raw_sid, &mut sid_pwstr) }.map_err(|source| {
            ElevateError::Win32 {
                operation: "ConvertSidToStringSidW",
                source,
            }
        })?;

        // Immediately transfer ownership of the allocated buffer to the RAII guard.
        let string_sid_guard = LocalAllocatedStringGuard { pointer: sid_pwstr };

        let sid_string = unsafe { string_sid_guard.pointer.to_string() }
            .map_err(|_| ElevateError::SidStringConversionFailed)?;

        Ok(sid_string)
    }
}
