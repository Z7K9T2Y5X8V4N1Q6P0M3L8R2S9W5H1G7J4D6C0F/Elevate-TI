//! Process and thread security token primitives.
//!
//! Provides RAII types for manipulating Windows security tokens, checking
//! group memberships, enabling privileges, and impersonating security contexts.

use std::{alloc::Layout, mem, ptr};

use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_SUCCESS, GetLastError, HANDLE, LUID, SetLastError, WIN32_ERROR,
        },
        Security::{
            AdjustTokenPrivileges, DuplicateTokenEx, EqualSid, GetTokenInformation,
            ImpersonateLoggedOnUser, LUID_AND_ATTRIBUTES, LookupPrivilegeValueW, PSID,
            RevertToSelf, SE_PRIVILEGE_ENABLED, SecurityImpersonation, SetTokenInformation,
            TOKEN_ACCESS_MASK, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS, TOKEN_GROUPS,
            TOKEN_INFORMATION_CLASS, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_TYPE, TOKEN_USER,
            TokenGroups, TokenImpersonation, TokenPrimary, TokenSessionId, TokenUser,
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

/// Generic RAII auto-closing handle guard for standard Win32 OS handles.
pub(crate) struct HandleGuard {
    handle: HANDLE,
}

impl Drop for HandleGuard {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

impl HandleGuard {
    /// Encapsulate a raw OS handle inside an RAII closer.
    pub const fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    /// Access the underlying raw handle without relinquishing ownership.
    pub const fn raw(&self) -> HANDLE {
        self.handle
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
    /// Encapsulate an existing raw Win32 token handle inside an RAII closer.
    pub const fn from_raw_handle(handle: HANDLE) -> Self {
        Self { handle }
    }

    /// Open the token belonging to the current application process.
    pub fn current_process() -> Result<Self, ElevateError> {
        Self::open(
            unsafe { GetCurrentProcess() },
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
        )
    }

    /// Open the security token belonging to a running process by its identifier.
    pub fn from_process_id(process_id: u32) -> Result<Self, ElevateError> {
        let raw_process_handle =
            win32_call!(OpenProcess(PROCESS_QUERY_INFORMATION, false, process_id))?;
        let process_handle_guard = HandleGuard::new(raw_process_handle);

        Self::open(
            process_handle_guard.raw(),
            TOKEN_ACCESS_MASK(MAXIMUM_ALLOWED),
        )
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
        let mut token_handle = HANDLE::default();
        win32_call!(OpenProcessToken(
            process_handle,
            desired_access,
            &mut token_handle
        ))?;

        Ok(Self {
            handle: token_handle,
        })
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

    /// Assign a specific Windows Session ID to this token.
    pub fn assign_session_id(&self, session_id: u32) -> Result<(), ElevateError> {
        win32_call!(SetTokenInformation(
            self.handle,
            TokenSessionId,
            ptr::from_ref(&session_id).cast(),
            mem::size_of::<u32>() as _,
        ))?;

        Ok(())
    }

    /// Query the Windows Session ID currently associated with this token.
    pub fn query_session_id(&self) -> Result<u32, ElevateError> {
        let mut session_id = 0u32;
        let mut return_length = 0u32;

        win32_call!(GetTokenInformation(
            self.handle,
            TokenSessionId,
            Some(ptr::from_mut(&mut session_id).cast()),
            mem::size_of::<u32>() as u32,
            &mut return_length,
        ))?;

        Ok(session_id)
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
        let aligned_buffer = query_token_information_buffer(self.handle, TokenUser, "TokenUser")?;
        let token_user = unsafe { &*aligned_buffer.as_ptr().cast::<TOKEN_USER>() };
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
        let aligned_buffer =
            query_token_information_buffer(self.handle, TokenGroups, "TokenGroups")?;
        Ok(TokenGroupsBuffer {
            _buffer: aligned_buffer,
        })
    }
}

/// Dynamically allocated buffer guaranteed to satisfy 8-byte pointer alignment.
struct AlignedTokenBuffer {
    pointer: *mut u8,
    layout: Layout,
}

impl Drop for AlignedTokenBuffer {
    fn drop(&mut self) {
        if !self.pointer.is_null() && self.layout.size() > 0 {
            unsafe {
                std::alloc::dealloc(self.pointer, self.layout);
            }
        }
    }
}

impl AlignedTokenBuffer {
    /// Allocate an aligned zero-initialized buffer with pointer alignment constraints.
    fn allocate(size_in_bytes: usize) -> Option<Self> {
        let layout = Layout::from_size_align(size_in_bytes, mem::align_of::<usize>()).ok()?;
        let pointer = unsafe { std::alloc::alloc_zeroed(layout) };
        if pointer.is_null() {
            None
        } else {
            Some(Self { pointer, layout })
        }
    }

    const fn as_ptr(&self) -> *const u8 {
        self.pointer
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.pointer
    }
}

/// Generic two-phase memory query helper returning an aligned dynamic buffer.
fn query_token_information_buffer(
    token_handle: HANDLE,
    information_class: TOKEN_INFORMATION_CLASS,
    class_name: &'static str,
) -> Result<AlignedTokenBuffer, ElevateError> {
    let mut required_size = 0u32;
    let _ = unsafe {
        GetTokenInformation(token_handle, information_class, None, 0, &mut required_size)
    };
    if required_size == 0 {
        return Err(ElevateError::TokenInformationBufferEmpty {
            information_class: class_name,
        });
    }

    let mut aligned_buffer = AlignedTokenBuffer::allocate(required_size as usize).ok_or(
        ElevateError::TokenInformationBufferEmpty {
            information_class: class_name,
        },
    )?;

    win32_call!(GetTokenInformation(
        token_handle,
        information_class,
        Some(aligned_buffer.as_mut_ptr().cast()),
        required_size,
        &mut required_size,
    ))?;

    Ok(aligned_buffer)
}

/// RAII wrapper managing an aligned dynamic buffer holding a [`TOKEN_GROUPS`] structure.
struct TokenGroupsBuffer {
    _buffer: AlignedTokenBuffer,
}

impl TokenGroupsBuffer {
    /// Expose safe borrowed references to each group `PSID`.
    fn iter(&self) -> impl Iterator<Item = PSID> + '_ {
        let token_groups = unsafe { &*self._buffer.as_ptr().cast::<TOKEN_GROUPS>() };
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
pub struct ImpersonationGuard;

impl Drop for ImpersonationGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = RevertToSelf();
        }
    }
}
