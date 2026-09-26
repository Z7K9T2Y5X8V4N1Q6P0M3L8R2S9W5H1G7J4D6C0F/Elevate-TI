//! Process management and fluent token-based process spawning.
//!
//! Provides [`ProcessSpawner`] to launch executables under custom security
//! tokens, and process enumeration utilities powered by `sysinfo`.

use std::{
    env,
    ffi::c_void,
    mem,
    path::PathBuf,
    ptr::{self},
};

use sysinfo::{Process, ProcessRefreshKind, ProcessesToUpdate, System};
use windows::{
    Win32::{
        Foundation::CloseHandle,
        System::{
            Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
            RemoteDesktop::WTSGetActiveConsoleSessionId,
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
    token: &'a ProcessToken,
    executable_path: Option<PathBuf>,
    desktop: HSTRING,
}

impl<'a> ProcessSpawner<'a> {
    /// Create a new process spawner bound to an elevated primary token.
    pub fn new_with_token(token: &'a ProcessToken) -> Self {
        Self {
            token,
            executable_path: None,
            desktop: HSTRING::new(),
        }
    }

    /// Set the target executable to the path of the current running binary.
    pub fn current_exe(mut self) -> Result<Self, ElevateError> {
        let binary_path = env::current_exe()?;
        self.executable_path = Some(binary_path);
        Ok(self)
    }

    /// Set the target desktop station name.
    pub fn desktop(mut self, desktop_name: &str) -> Self {
        self.desktop = HSTRING::from(desktop_name);
        self
    }

    /// Spawn the target process under the elevated token.
    pub fn spawn(self) -> Result<(), ElevateError> {
        let executable_path = self
            .executable_path
            .ok_or(ElevateError::ExecutablePathMissing)?;

        let environment_block_guard = EnvironmentBlockGuard::create(self.token)?;

        let mut command_line_buffer: Vec<u16> = format!("\"{}\"\0", executable_path.display())
            .encode_utf16()
            .collect();

        let current_directory = env::current_dir()?;
        let current_directory_hstring = HSTRING::from(current_directory.as_os_str());

        let mut startup_info = STARTUPINFOW {
            cb: mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(self.desktop.as_ptr().cast_mut()),
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: SW_SHOWNORMAL.0 as u16,
            ..Default::default()
        };

        let mut process_information_guard = ProcessInformationGuard::default();

        // Use flag value 0 (no profile load) because service accounts
        // like TrustedInstaller do not own standard user profile registry hives.
        win32_call!(CreateProcessWithTokenW(
            self.token.raw(),
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

/// Retrieve the active console session ID for the current interactive desktop.
pub fn get_active_session_id() -> u32 {
    unsafe { WTSGetActiveConsoleSessionId() }
}

/// Find a genuine SYSTEM process ID by its executable name within the active console session.
///
/// Matches the process name, ensures it runs in the active console session, and validates
/// that the process belongs to `NT AUTHORITY\SYSTEM` (S-1-5-18).
pub fn find_process_id_by_name(target_process_name: &str) -> Result<u32, ElevateError> {
    let active_session_id = get_active_session_id();

    let mut system_monitor = System::new();
    system_monitor.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing(),
    );

    for (process_id, process) in system_monitor.processes() {
        if is_matching_system_process(process, target_process_name, active_session_id) {
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
    let token = match ProcessToken::from_process_id(candidate_process_id) {
        Ok(valid_token) => valid_token,
        Err(_) => return false,
    };

    let session_id = match token.query_session_id() {
        Ok(retrieved_session) => retrieved_session,
        Err(_) => return false,
    };

    if session_id != target_session_id {
        return false;
    }

    let user_sid = match token.query_user_sid_string() {
        Ok(valid_sid) => valid_sid,
        Err(_) => return false,
    };

    user_sid == LOCAL_SYSTEM_SID
}

/// RAII guard wrapping an environment block allocated by `CreateEnvironmentBlock`.
struct EnvironmentBlockGuard {
    block: *mut c_void,
}

impl Drop for EnvironmentBlockGuard {
    fn drop(&mut self) {
        if !self.block.is_null() {
            unsafe {
                let _ = DestroyEnvironmentBlock(self.block);
            }
        }
    }
}

impl EnvironmentBlockGuard {
    /// Allocate an environment block specifically tailored to the given token.
    fn create(token: &ProcessToken) -> Result<Self, ElevateError> {
        let mut block = ptr::null_mut();
        win32_call!(CreateEnvironmentBlock(&mut block, token.raw(), false))?;
        Ok(Self { block })
    }

    /// Provide the raw environment block pointer expected by `CreateProcessWithTokenW`.
    fn as_raw_ptr(&self) -> Option<*const c_void> {
        if self.block.is_null() {
            None
        } else {
            Some(self.block.cast_const())
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
