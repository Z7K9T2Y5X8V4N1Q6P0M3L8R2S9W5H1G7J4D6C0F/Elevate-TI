//! Process and thread security token primitives.
//!
//! Provides RAII types for manipulating Windows security tokens, checking
//! group memberships, enabling privileges, and impersonating security contexts.

use std::{mem, ptr};

use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, LUID, SetLastError, WIN32_ERROR,
        },
        Security::{
            AdjustTokenPrivileges, DuplicateTokenEx, EqualSid, GetTokenInformation,
            ImpersonateLoggedOnUser, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, PSID,
            RevertToSelf, SE_PRIVILEGE_ENABLED, SecurityImpersonation, TOKEN_ACCESS_MASK,
            TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_GROUPS, TOKEN_INFORMATION_CLASS,
            TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_TYPE, TOKEN_USER, TokenGroups, TokenImpersonation,
            TokenPrimary, TokenUser,
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

use super::{macros::win32_call, sid::Sid};
use crate::error::ElevateError;

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

    const fn as_static_str(self) -> &'static str {
        match self {
            Self::Debug => "SeDebugPrivilege",
            Self::Impersonate => "SeImpersonatePrivilege",
        }
    }
}

/// Strongly-typed RAII guard holding an open process or thread token.
pub struct ProcessToken {
    handle: HANDLE,
}

impl Drop for ProcessToken {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

impl ProcessToken {
    /// Open the token belonging to the current application process.
    pub fn current_process() -> Result<Self, ElevateError> {
        Self::open(
            unsafe { GetCurrentProcess() },
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        )
    }

    /// Open the security token belonging to a running process by its identifier.
    pub fn from_process_id(process_id: u32) -> Result<Self, ElevateError> {
        let process_handle =
            win32_call!(OpenProcess(PROCESS_QUERY_INFORMATION, false, process_id))?;

        let token_result = Self::open(process_handle, TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED));
        unsafe {
            let _ = CloseHandle(process_handle);
        }

        token_result
    }

    /// Retrieve the underlying raw Win32 token handle.
    pub const fn raw(&self) -> HANDLE {
        self.handle
    }

    /// Open a process token with the requested access mask.
    fn open(
        process_handle: HANDLE,
        desired_access: TOKEN_ACCESS_MASK,
    ) -> Result<Self, ElevateError> {
        let mut handle = HANDLE::default();
        win32_call!(OpenProcessToken(
            process_handle,
            desired_access,
            &mut handle
        ))?;

        Ok(Self { handle })
    }

    /// Duplicate this token as either a Primary or Impersonation token.
    pub fn duplicate(&self, token_type: TokenType) -> Result<Self, ElevateError> {
        let access_mask = match token_type {
            TokenType::Primary => TOKEN_ALL_ACCESS,
            TokenType::Impersonation => TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED),
        };

        let mut duplicated_handle = HANDLE::default();
        win32_call!(DuplicateTokenEx(
            self.handle,
            access_mask,
            None,
            SecurityImpersonation,
            token_type.to_raw(),
            &mut duplicated_handle,
        ))?;

        Ok(Self {
            handle: duplicated_handle,
        })
    }

    /// Impersonate this token on the current thread, returning an RAII guard.
    pub fn impersonate(&self) -> Result<ImpersonationGuard, ElevateError> {
        win32_call!(ImpersonateLoggedOnUser(self.handle))?;
        Ok(ImpersonationGuard)
    }

    /// Enable specified privileges on this token.
    pub fn enable_privileges(&self, privileges: &[Privilege]) -> Result<(), ElevateError> {
        for &privilege in privileges {
            self.enable_single_privilege(privilege)?;
        }
        Ok(())
    }

    /// Enable a single privilege using its wide-character name.
    fn enable_single_privilege(&self, privilege: Privilege) -> Result<(), ElevateError> {
        let mut privilege_luid = LUID::default();
        win32_call!(LookupPrivilegeValueW(
            PCWSTR::null(),
            privilege.as_pcwstr(),
            &mut privilege_luid
        ))?;

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
        win32_call!(AdjustTokenPrivileges(
            self.handle,
            false,
            Some(ptr::from_ref(&token_privileges)),
            mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        ))?;

        let last_os_error = unsafe { GetLastError() };
        if last_os_error != ERROR_SUCCESS {
            return Err(ElevateError::PrivilegeNotAssigned {
                privilege_name: privilege.as_static_str(),
                error_code: last_os_error.0,
            });
        }

        Ok(())
    }

    /// Retrieve the owner user SID string of this token.
    pub fn query_user_sid_string(&self) -> Result<String, ElevateError> {
        let buffer = query_token_information_buffer(self.handle, TokenUser, "TokenUser")?;
        let token_user = unsafe { &*(buffer.as_ptr().cast::<TOKEN_USER>()) };
        Sid::to_string_from_raw(token_user.User.Sid)
    }

    /// Check whether this token holds membership in the specified SID string.
    pub fn contains_sid_string(&self, target_sid_string: PCWSTR) -> Result<bool, ElevateError> {
        let target_sid = Sid::parse(target_sid_string)?;
        let groups = self.query_groups()?;

        Ok(groups
            .iter()
            .any(|group_sid| are_sids_equal(group_sid, target_sid.raw())))
    }

    /// Safely query and retrieve all groups associated with this token.
    fn query_groups(&self) -> Result<TokenGroupsBuffer, ElevateError> {
        let buffer = query_token_information_buffer(self.handle, TokenGroups, "TokenGroups")?;
        Ok(TokenGroupsBuffer { buffer })
    }
}

/// Generic two-phase memory query helper for token information classes.
fn query_token_information_buffer(
    token_handle: HANDLE,
    information_class: TOKEN_INFORMATION_CLASS,
    class_name: &'static str,
) -> Result<Vec<u8>, ElevateError> {
    let mut required_size = 0u32;
    let _ = unsafe {
        GetTokenInformation(token_handle, information_class, None, 0, &mut required_size)
    };
    if required_size == 0 {
        return Err(ElevateError::TokenInformationBufferEmpty {
            information_class: class_name,
        });
    }

    let mut buffer = vec![0u8; required_size as usize];
    win32_call!(GetTokenInformation(
        token_handle,
        information_class,
        Some(buffer.as_mut_ptr().cast()),
        required_size,
        &mut required_size,
    ))?;

    Ok(buffer)
}

/// RAII wrapper managing the raw dynamic buffer holding a [`TOKEN_GROUPS`] structure.
struct TokenGroupsBuffer {
    buffer: Vec<u8>,
}

impl TokenGroupsBuffer {
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

/// Binary equality check on two raw PSIDs via Win32 `EqualSid`.
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
