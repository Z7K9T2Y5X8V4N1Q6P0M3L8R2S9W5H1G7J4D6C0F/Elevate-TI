//! Process and thread security token primitives.
//!
//! Provides RAII types for manipulating Windows security tokens, checking
//! group memberships, enabling privileges, and impersonating security contexts.

use std::{mem, ptr};

use anyhow::{Context, Result, anyhow};
use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, LUID, SetLastError, WIN32_ERROR,
        },
        Security::{
            AdjustTokenPrivileges, DuplicateTokenEx, EqualSid, GetTokenInformation,
            ImpersonateLoggedOnUser, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, PSID,
            RevertToSelf, SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_ACCESS_MASK,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_GROUPS, TOKEN_PRIVILEGES, TOKEN_QUERY,
            TOKEN_TYPE, TOKEN_USER, TokenGroups, TokenImpersonation, TokenPrimary, TokenUser,
        },
        System::{
            SystemServices::MAXIMUM_ALLOWED,
            Threading::{
                GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
            },
        },
    },
    core::{PCWSTR, w},
};

use super::sid::Sid;

/// Target token type when duplicating an existing security token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// Primary token for creating new process instances.
    Primary,
    /// Impersonation token for executing within a specific thread security context.
    Impersonation,
}

impl TokenType {
    const fn to_raw(self) -> TOKEN_TYPE {
        match self {
            Self::Primary => TokenPrimary,
            Self::Impersonation => TokenImpersonation,
        }
    }
}

/// Supported administrative security privileges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    /// Debug programs (`SeDebugPrivilege`).
    Debug,
    /// Impersonate a client after authentication (`SeImpersonatePrivilege`).
    Impersonate,
}

impl Privilege {
    const fn as_pcwstr(self) -> PCWSTR {
        match self {
            Self::Debug => w!("SeDebugPrivilege"),
            Self::Impersonate => w!("SeImpersonatePrivilege"),
        }
    }
}

/// Strongly-typed RAII guard holding an open process or thread token.
pub struct ProcessToken {
    handle: HANDLE,
}

impl Drop for ProcessToken {
    fn drop(&mut self) {
        if !self.handle.is_invalid() && !self.handle.0.is_null() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

impl ProcessToken {
    /// Open the token belonging to the current application process.
    pub fn current_process() -> Result<Self> {
        Self::open(
            unsafe { GetCurrentProcess() },
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        )
        .context("Failed to open current process token")
    }

    /// Open the security token belonging to a running process by its identifier.
    pub fn from_process_id(process_id: u32) -> Result<Self> {
        let process_handle = unsafe { OpenProcess(PROCESS_QUERY_INFORMATION, false, process_id) }
            .map_err(|windows_error| {
            anyhow!(
                "OpenProcess failed for PID {process_id} (Win32 Error: 0x{:08X}): {windows_error}",
                windows_error.code().0
            )
        })?;

        let token_result = Self::open(process_handle, TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED));
        unsafe {
            let _ = CloseHandle(process_handle);
        }

        token_result.with_context(|| format!("OpenProcessToken failed for PID {process_id}"))
    }

    /// Retrieve the underlying raw Win32 token handle.
    pub const fn raw(&self) -> HANDLE {
        self.handle
    }

    /// Open a process token with the requested access mask.
    fn open(process_handle: HANDLE, desired_access: TOKEN_ACCESS_MASK) -> Result<Self> {
        let mut handle = HANDLE::default();
        unsafe { OpenProcessToken(process_handle, desired_access, &mut handle) }
            .context("OpenProcessToken Win32 call failed")?;

        Ok(Self { handle })
    }

    /// Duplicate this token as either a Primary or Impersonation token.
    pub fn duplicate(&self, token_type: TokenType) -> Result<Self> {
        let access_mask = match token_type {
            TokenType::Primary => TOKEN_ALL_ACCESS,
            TokenType::Impersonation => TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED),
        };

        let mut duplicated_handle = HANDLE::default();
        unsafe {
            DuplicateTokenEx(
                self.handle,
                access_mask,
                None,
                SecurityImpersonation,
                token_type.to_raw(),
                &mut duplicated_handle,
            )
        }
        .context("DuplicateTokenEx failed")?;

        Ok(Self {
            handle: duplicated_handle,
        })
    }

    /// Impersonate this token on the current thread, returning an RAII guard.
    pub fn impersonate(&self) -> Result<ImpersonationGuard> {
        unsafe { ImpersonateLoggedOnUser(self.handle) }
            .context("ImpersonateLoggedOnUser failed")?;

        Ok(ImpersonationGuard)
    }

    /// Enable specified privileges on this token.
    pub fn enable_privileges(&self, privileges: &[Privilege]) -> Result<()> {
        for &privilege in privileges {
            self.enable_single_privilege(privilege.as_pcwstr())?;
        }
        Ok(())
    }

    /// Enable a single privilege using its wide-character name.
    fn enable_single_privilege(&self, privilege_name: PCWSTR) -> Result<()> {
        let mut privilege_luid = LUID::default();
        unsafe { LookupPrivilegeValueW(PCWSTR::null(), privilege_name, &mut privilege_luid) }
            .context("LookupPrivilegeValueW failed")?;

        let token_privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: privilege_luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        // Reset the thread last-error before invocation because AdjustTokenPrivileges can
        // return success while still setting ERROR_NOT_ALL_ASSIGNED.
        unsafe { SetLastError(WIN32_ERROR(0)) };
        let adjust_token_privilegs_result = unsafe {
            AdjustTokenPrivileges(
                self.handle,
                false,
                Some(ptr::from_ref(&token_privileges)),
                mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                None,
                None,
            )
        };
        let last_os_error = unsafe { GetLastError() };

        adjust_token_privilegs_result.context("AdjustTokenPrivileges call failed")?;

        if last_os_error != ERROR_SUCCESS {
            return Err(anyhow!(
                "AdjustTokenPrivileges partial failure: 0x{:08X}",
                last_os_error.0
            ));
        }

        Ok(())
    }

    /// Retrieve the owner user SID string of this token.
    pub fn query_user_sid_string(&self) -> Result<String> {
        let mut required_size = 0u32;
        let _ = unsafe { GetTokenInformation(self.handle, TokenUser, None, 0, &mut required_size) };
        if required_size == 0 {
            return Err(anyhow!("Failed to query token user size"));
        }

        let mut buffer = vec![0u8; required_size as usize];
        unsafe {
            GetTokenInformation(
                self.handle,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                required_size,
                &mut required_size,
            )
        }
        .context("Failed to retrieve token user information")?;

        let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        Sid::to_string_from_raw(token_user.User.Sid)
    }

    /// Check whether this token holds membership in the specified SID string.
    pub fn contains_sid_string(&self, target_sid_string: PCWSTR) -> Result<bool> {
        let target_sid = Sid::parse(target_sid_string)?;
        let groups = self.query_groups()?;

        Ok(groups
            .iter()
            .any(|group_sid| are_sids_equal(group_sid, target_sid.raw())))
    }

    /// Safely query and retrieve all groups associated with this token.
    fn query_groups(&self) -> Result<TokenGroupsBuffer> {
        TokenGroupsBuffer::query_from_token(self.handle)
    }
}

/// RAII wrapper managing the raw dynamic buffer holding a [`TOKEN_GROUPS`] structure.
struct TokenGroupsBuffer {
    buffer: Vec<u8>,
}

impl TokenGroupsBuffer {
    /// Perform the Win32 two-phase query to populate token groups memory.
    fn query_from_token(token_handle: HANDLE) -> Result<Self> {
        let mut required_size = 0u32;
        let _ =
            unsafe { GetTokenInformation(token_handle, TokenGroups, None, 0, &mut required_size) };
        if required_size == 0 {
            return Err(anyhow!("Failed to query token groups memory size"));
        }

        let mut buffer = vec![0u8; required_size as usize];
        unsafe {
            GetTokenInformation(
                token_handle,
                TokenGroups,
                Some(buffer.as_mut_ptr().cast()),
                required_size,
                &mut required_size,
            )
        }
        .context("Failed to retrieve token groups information")?;

        Ok(Self { buffer })
    }

    /// Expose safe borrowed references to each group `PSID`.
    fn iter(&self) -> impl Iterator<Item = PSID> + '_ {
        let token_groups = unsafe { &*(self.buffer.as_ptr().cast::<TOKEN_GROUPS>()) };
        let slice = unsafe {
            std::slice::from_raw_parts(
                token_groups.Groups.as_ptr(),
                token_groups.GroupCount as usize,
            )
        };
        slice.iter().map(|group| group.Sid)
    }
}

/// Helper function to perform binary equality check on two raw PSIDs via Win32 `EqualSid`.
fn are_sids_equal(first_sid: PSID, second_sid: PSID) -> bool {
    unsafe { EqualSid(first_sid, second_sid) }.is_ok()
}

/// RAII guard representing active thread impersonation.
///
/// Automatically calls [`RevertToSelf`] upon being dropped to guarantee
/// no privileged security context leaks across operations.
pub struct ImpersonationGuard;

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = RevertToSelf();
        }
    }
}
