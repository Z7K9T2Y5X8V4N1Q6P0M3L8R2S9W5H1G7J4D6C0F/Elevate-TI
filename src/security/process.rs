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

use anyhow::{Context, Result, anyhow};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use windows::{
    Win32::{
        Foundation::CloseHandle,
        System::{
            Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
            Threading::{
                CREATE_UNICODE_ENVIRONMENT, CreateProcessWithTokenW, LOGON_WITH_PROFILE,
                PROCESS_INFORMATION, STARTF_USESHOWWINDOW, STARTUPINFOW,
            },
        },
        UI::WindowsAndMessaging::SW_SHOWNORMAL,
    },
    core::{HSTRING, PCWSTR, PWSTR},
};

use super::token::ProcessToken;

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
            desktop: HSTRING::from("WinSta0\\Default"),
        }
    }

    /// Set the target executable to the path of the current running binary.
    pub fn current_exe(mut self) -> Result<Self> {
        self.executable_path =
            Some(env::current_exe().context("Failed to get current executable path")?);
        Ok(self)
    }

    /// Set the target desktop station name.
    pub fn desktop(mut self, desktop_name: &str) -> Self {
        self.desktop = HSTRING::from(desktop_name);
        self
    }

    /// Spawn the target process under the elevated token.
    pub fn spawn(self) -> Result<()> {
        let executable_path = self
            .executable_path
            .ok_or_else(|| anyhow!("Target executable path was not specified"))?;

        // 1. Create an environment block RAII guard for the target token.
        let environment_block_guard = EnvironmentBlockGuard::create(self.token)?;

        // 2. Format the command line with standard quoting and null-terminator.
        let mut command_line_buffer: Vec<u16> = format!("\"{}\"\0", executable_path.display())
            .encode_utf16()
            .collect();

        let current_directory =
            env::current_dir().context("Failed to retrieve current working directory")?;
        let current_directory_hstring = HSTRING::from(current_directory.as_os_str());

        let mut startup_info = STARTUPINFOW {
            cb: mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(self.desktop.as_ptr().cast_mut()),
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: SW_SHOWNORMAL.0 as u16,
            ..Default::default()
        };

        // 3. Prepare the process information RAII guard to hold output handles.
        let mut process_information_guard = ProcessInformationGuard::default();

        unsafe {
            CreateProcessWithTokenW(
                self.token.raw(),
                LOGON_WITH_PROFILE,
                PCWSTR::null(),
                PWSTR(command_line_buffer.as_mut_ptr()),
                CREATE_UNICODE_ENVIRONMENT,
                environment_block_guard.as_raw_ptr(),
                &current_directory_hstring,
                &mut startup_info,
                process_information_guard.as_raw_mut(),
            )
        }
        .map_err(|windows_error| {
            anyhow!(
                "CreateProcessWithTokenW failed (Win32 Error: 0x{:08X}): {windows_error}",
                windows_error.code().0
            )
        })?;

        // Both environment_block_guard and process_information_guard will
        // automatically drop and release their underlying Win32 resources cleanly here.
        Ok(())
    }
}

/// Find a genuine SYSTEM process ID by its executable name.
///
/// Matches the process name and validates that the process belongs to `NT AUTHORITY\SYSTEM` (S-1-5-18),
/// preventing spoofed user processes from hijacking elevation flow.
pub fn find_process_id_by_name(target_process_name: &str) -> Result<u32> {
    let mut system_monitor = System::new();
    system_monitor.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing(),
    );

    system_monitor
        .processes()
        .iter()
        .find_map(|(process_id, process)| {
            let process_name = process.name().to_string_lossy();
            if !process_name.eq_ignore_ascii_case(target_process_name) {
                return None;
            }

            let candidate_pid = process_id.as_u32();

            let token = ProcessToken::from_process_id(candidate_pid).ok()?;
            let user_sid = token.query_user_sid_string().ok()?;

            if user_sid == LOCAL_SYSTEM_SID {
                Some(candidate_pid)
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("Genuine SYSTEM process '{target_process_name}' not found"))
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
    fn create(token: &ProcessToken) -> Result<Self> {
        let mut block = ptr::null_mut();
        unsafe {
            CreateEnvironmentBlock(&mut block, token.raw(), false)
                .context("CreateEnvironmentBlock call failed")?;
        }

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
        if !self.information.hProcess.is_invalid() && !self.information.hProcess.0.is_null() {
            let _ = unsafe { CloseHandle(self.information.hProcess) };
        }
        if !self.information.hThread.is_invalid() && !self.information.hThread.0.is_null() {
            let _ = unsafe { CloseHandle(self.information.hThread) };
        }
    }
}

impl ProcessInformationGuard {
    /// Retrieve a mutable pointer to the inner [`PROCESS_INFORMATION`] structure.
    fn as_raw_mut(&mut self) -> *mut PROCESS_INFORMATION {
        &mut self.information
    }
}
