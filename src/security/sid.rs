//! Strongly-typed Windows Security Identifier (SID) wrapper.
//!
//! Encapsulates raw Win32 `PSID` allocation and provides safe RAII
//! deallocation via [`windows::Win32::Foundation::LocalFree`].

use anyhow::{Context, Result};
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

/// Strongly-typed RAII wrapper for a Windows Security Identifier (SID).
pub struct Sid {
    raw_sid: PSID,
}

impl Drop for Sid {
    fn drop(&mut self) {
        if !self.raw_sid.is_invalid() && !self.raw_sid.0.is_null() {
            unsafe {
                let _ = LocalFree(HLOCAL(self.raw_sid.0));
            }
        }
    }
}

impl Sid {
    /// Parse a security identifier from a wide string constant.
    pub fn parse(sid_string: PCWSTR) -> Result<Self> {
        let mut raw_sid = PSID::default();
        unsafe { ConvertStringSidToSidW(sid_string, &mut raw_sid) }
            .context("ConvertStringSidToSidW failed to parse SID")?;

        Ok(Self { raw_sid })
    }

    /// Retrieve the underlying raw `PSID`.
    pub const fn raw(&self) -> PSID {
        self.raw_sid
    }

    /// Convert a raw `PSID` into its standard string representation.
    pub fn to_string_from_raw(raw_sid: PSID) -> Result<String> {
        let mut sid_pwstr = PWSTR::null();
        unsafe { ConvertSidToStringSidW(raw_sid, &mut sid_pwstr) }
            .context("ConvertSidToStringSidW failed")?;

        let sid_string = unsafe { sid_pwstr.to_string() }
            .context("Failed to parse SID string buffer as UTF-8")?;

        unsafe {
            let _ = LocalFree(HLOCAL(sid_pwstr.0.cast()));
        }

        Ok(sid_string)
    }
}
