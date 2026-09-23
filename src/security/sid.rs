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

use super::macros::win32_call;
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

impl LocalAllocatedStringGuard {
    /// Convert the inner null-terminated wide string into a standard Rust [`String`].
    fn into_string(self) -> Result<String, ElevateError> {
        unsafe { self.pointer.to_string() }.map_err(|_| ElevateError::SidStringConversionFailed)
    }
}

impl Sid {
    /// Parse a security identifier from a wide string constant.
    pub fn parse(sid_string: PCWSTR) -> Result<Self, ElevateError> {
        let mut raw_sid = PSID::default();
        win32_call!(ConvertStringSidToSidW(sid_string, &mut raw_sid))?;
        Ok(Self { raw_sid })
    }

    /// Retrieve the underlying raw `PSID`.
    pub const fn raw(&self) -> PSID {
        self.raw_sid
    }

    /// Convert a raw `PSID` into its standard string representation.
    pub fn to_string_from_raw(raw_sid: PSID) -> Result<String, ElevateError> {
        let mut sid_pwstr = PWSTR::null();
        win32_call!(ConvertSidToStringSidW(raw_sid, &mut sid_pwstr))?;

        LocalAllocatedStringGuard { pointer: sid_pwstr }.into_string()
    }
}
