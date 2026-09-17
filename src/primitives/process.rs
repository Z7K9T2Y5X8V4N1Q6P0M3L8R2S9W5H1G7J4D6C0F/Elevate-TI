//! Process management and fluent token-based process spawning.
//!
//! Provides [`ProcessSpawner`] to launch executables under custom security
//! tokens, and process enumeration utilities powered by `sysinfo`.

use std::{env, mem, path::PathBuf, ptr};

use anyhow::{Context, Result, anyhow};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System};
use windows::{
    Win32::{
        Foundation::{CloseHandle, GetLastError},
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
        let exe_path = self
            .executable_path
            .ok_or_else(|| anyhow!("Target executable path was not specified"))?;

        let mut environment_block = ptr::null_mut();
        let _ = unsafe { CreateEnvironmentBlock(&mut environment_block, self.token.raw(), false) };

        // Win32 CreateProcess expects a mutable PWSTR buffer for lpCommandLine,
        // so we format the quoted string directly with a trailing null terminator.
        let mut command_line_buffer: Vec<u16> = format!("\"{}\"\0", exe_path.display())
            .encode_utf16()
            .collect();

        let current_directory =
            env::current_dir().context("Failed to retrieve current working directory")?;
        let current_directory_hstring = HSTRING::from(current_directory.as_os_str());

        // HSTRING provides PCWSTR automatically via as_ptr(), cast to mutable for lpDesktop.
        let mut startup_info = STARTUPINFOW {
            cb: mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(self.desktop.as_ptr().cast_mut()),
            dwFlags: STARTF_USESHOWWINDOW,
            wShowWindow: SW_SHOWNORMAL.0 as u16,
            ..Default::default()
        };

        let mut process_information = PROCESS_INFORMATION::default();

        let creation_result = unsafe {
            CreateProcessWithTokenW(
                self.token.raw(),
                LOGON_WITH_PROFILE,
                PCWSTR::null(),
                PWSTR(command_line_buffer.as_mut_ptr()),
                CREATE_UNICODE_ENVIRONMENT,
                Some(environment_block),
                &current_directory_hstring,
                &mut startup_info,
                &mut process_information,
            )
        };

        if !environment_block.is_null() {
            unsafe {
                let _ = DestroyEnvironmentBlock(environment_block);
            }
        }

        creation_result.with_context(|| {
            let win32_error = unsafe { GetLastError() };
            format!(
                "CreateProcessWithTokenW failed (Win32 Error: 0x{:08X})",
                win32_error.0
            )
        })?;

        unsafe {
            let _ = CloseHandle(process_information.hProcess);
            let _ = CloseHandle(process_information.hThread);
        }

        Ok(())
    }
}

/// Find a process ID by its executable name using `sysinfo`.
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
            if process_name.eq_ignore_ascii_case(target_process_name) {
                Some(process_id.as_u32())
            } else {
                None
            }
        })
        .ok_or_else(|| anyhow!("Process '{target_process_name}' not found in active processes"))
}
