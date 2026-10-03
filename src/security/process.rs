//! Process management and fluent token-based process spawning.
//!
//! Provides [`ProcessSpawner`] to launch executables under custom security
//! tokens, and process enumeration utilities powered by `sysinfo`.

use std::{
    env,
    ffi::c_void,
    mem,
    path::{Path, PathBuf},
    ptr,
};

use sysinfo::{Process, ProcessRefreshKind, ProcessesToUpdate, System};
use windows::{
    Win32::{
        Foundation::CloseHandle,
        System::{
            Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
            Threading::{
                CREATE_PROCESS_LOGON_FLAGS, CREATE_UNICODE_ENVIRONMENT, CreateProcessWithTokenW,
                PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTUPINFOW,
            },
        },
        UI::WindowsAndMessaging::SW_SHOWNORMAL,
    },
    core::{HSTRING, PCWSTR, PWSTR},
};

use super::{macros::win32_call, token::ProcessToken};
use crate::error::ElevateError;

/// Well-Known Local System Account SID (`NT AUTHORITY\SYSTEM`).
const LOCAL_SYSTEM_SID: &str = "S-1-5-18";

/// Fluent builder for launching a process using a duplicated primary token.
pub struct ProcessSpawner<'a> {
    primary_token: &'a ProcessToken,
    executable_path: Option<PathBuf>,
    command_line: Option<String>,
    desktop: HSTRING,
}

impl<'a> ProcessSpawner<'a> {
    /// Create a new process spawner bound to an elevated primary token.
    pub fn new_with_token(primary_token: &'a ProcessToken) -> Self {
        Self {
            primary_token,
            executable_path: None,
            command_line: None,
            desktop: HSTRING::new(),
        }
    }

    /// Set the target executable to the path of the current running binary.
    pub fn current_exe(mut self) -> Result<Self, ElevateError> {
        let binary_path = env::current_exe()?;
        self.executable_path = Some(binary_path);
        Ok(self)
    }

    /// Set an arbitrary target executable path.
    pub fn executable_path(mut self, path: impl AsRef<Path>) -> Self {
        self.executable_path = Some(path.as_ref().to_path_buf());
        self
    }

    /// Set a custom command line string to pass to the process.
    pub fn command_line(mut self, command_line: impl Into<String>) -> Self {
        self.command_line = Some(command_line.into());
        self
    }

    /// Set the target desktop station name.
    pub fn desktop(mut self, desktop_name: &str) -> Self {
        self.desktop = HSTRING::from(desktop_name);
        self
    }

    /// Spawn the target process under the provided token.
    pub fn spawn(self) -> Result<(), ElevateError> {
        let command_line_string = if let Some(custom_command_line) = self.command_line {
            custom_command_line
        } else if let Some(ref executable_path) = self.executable_path {
            format!("\"{}\"", executable_path.display())
        } else {
            return Err(ElevateError::ExecutablePathMissing);
        };

        let environment_block_guard = EnvironmentBlockGuard::create(self.primary_token)?;

        let mut command_line_buffer: Vec<u16> = command_line_string
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

        let current_directory = env::current_dir()?;
        let current_directory_hstring = HSTRING::from(current_directory.as_os_str());

        let mut startup_info = STARTUPINFOW {
            cb: mem::size_of::<STARTUPINFOW>() as _,
            lpDesktop: PWSTR(self.desktop.as_ptr().cast_mut()),
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: SW_SHOWNORMAL.0 as u16,
            ..Default::default()
        };

        let mut process_information_guard = ProcessInformationGuard::default();

        // Use flag value 0 (no profile load) because service accounts
        // like TrustedInstaller do not own standard user profile registry hives.
        win32_call!(CreateProcessWithTokenW(
            self.primary_token.raw(),
            CREATE_PROCESS_LOGON_FLAGS(0),
            PCWSTR::null(),
            PWSTR(command_line_buffer.as_mut_ptr()),
            CREATE_UNICODE_ENVIRONMENT,
            environment_block_guard.as_raw_ptr(),
            &current_directory_hstring,
            &mut startup_info,
            process_information_guard.as_raw_mut(),
        ))?;

        Ok(())
    }
}

/// Find a genuine SYSTEM process ID by its executable name within a designated session.
///
/// Matches the process name, ensures it runs in the specified session ID, and validates
/// that the process belongs to `NT AUTHORITY\SYSTEM` (S-1-5-18).
pub fn find_process_id_by_name(
    target_process_name: &str,
    target_session_id: u32,
) -> Result<u32, ElevateError> {
    let mut system_monitor = System::new();
    system_monitor.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing(),
    );

    for (process_id, process) in system_monitor.processes() {
        if is_matching_system_process(process, target_process_name, target_session_id) {
            return Ok(process_id.as_u32());
        }
    }

    Err(ElevateError::SystemProcessNotFound {
        process_name: target_process_name.to_string(),
    })
}

/// Check if a process matches the requested name, active session, and `NT AUTHORITY\SYSTEM` ownership.
fn is_matching_system_process(
    process: &Process,
    target_process_name: &str,
    target_session_id: u32,
) -> bool {
    let process_name = process.name().to_string_lossy();
    if !process_name.eq_ignore_ascii_case(target_process_name) {
        return false;
    }

    let candidate_process_id = process.pid().as_u32();
    let candidate_process_token = match ProcessToken::from_process_id(candidate_process_id) {
        Ok(candidate_process_token) => candidate_process_token,
        Err(_) => return false,
    };

    let candidate_session_id = match candidate_process_token.query_session_id() {
        Ok(candidate_session_id) => candidate_session_id,
        Err(_) => return false,
    };

    if candidate_session_id != target_session_id {
        return false;
    }

    let candidate_user_sid = match candidate_process_token.query_user_sid_string() {
        Ok(candidate_user_sid) => candidate_user_sid,
        Err(_) => return false,
    };

    candidate_user_sid == LOCAL_SYSTEM_SID
}

/// RAII guard wrapping an environment block allocated by `CreateEnvironmentBlock`.
struct EnvironmentBlockGuard {
    environment_block_pointer: *mut c_void,
}

impl Drop for EnvironmentBlockGuard {
    fn drop(&mut self) {
        if !self.environment_block_pointer.is_null() {
            unsafe {
                let _ = DestroyEnvironmentBlock(self.environment_block_pointer);
            }
        }
    }
}

impl EnvironmentBlockGuard {
    /// Allocate an environment block specifically tailored to the given token.
    fn create(token: &ProcessToken) -> Result<Self, ElevateError> {
        let mut environment_block_pointer = ptr::null_mut();
        win32_call!(CreateEnvironmentBlock(
            &mut environment_block_pointer,
            token.raw(),
            false
        ))?;
        Ok(Self {
            environment_block_pointer,
        })
    }

    /// Provide the raw environment block pointer expected by `CreateProcessWithTokenW`.
    fn as_raw_ptr(&self) -> Option<*const c_void> {
        if self.environment_block_pointer.is_null() {
            None
        } else {
            Some(self.environment_block_pointer.cast_const())
        }
    }
}

/// RAII guard managing process and primary thread handles inside [`PROCESS_INFORMATION`].
#[derive(Default)]
struct ProcessInformationGuard {
    information: PROCESS_INFORMATION,
}

impl Drop for ProcessInformationGuard {
    fn drop(&mut self) {
        if !self.information.hProcess.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.information.hProcess);
            }
        }
        if !self.information.hThread.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.information.hThread);
            }
        }
    }
}

impl ProcessInformationGuard {
    /// Retrieve a mutable pointer to the inner [`PROCESS_INFORMATION`] structure.
    fn as_raw_mut(&mut self) -> *mut PROCESS_INFORMATION {
        &mut self.information
    }
}
