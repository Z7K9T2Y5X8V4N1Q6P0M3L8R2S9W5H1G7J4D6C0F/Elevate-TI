//! Windows Service Control Manager and Service handle management.
//!
//! Provides RAII handles for connecting to the SCM, querying service
//! states, and safely waiting for a service to reach running status.

use std::{
    mem, ptr,
    thread::sleep,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow};
use windows::{
    Win32::{
        Foundation::{ERROR_SERVICE_ALREADY_RUNNING, GetLastError},
        System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
            SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
            SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS_PROCESS,
            SERVICE_STOP_PENDING, SERVICE_STOPPED, StartServiceW,
        },
    },
    core::PCWSTR,
};

/// RAII handle wrapping an active Service Control Manager connection.
pub struct ServiceManager {
    handle: SC_HANDLE,
}

impl Drop for ServiceManager {
    fn drop(&mut self) {
        if !self.handle.is_invalid() && !self.handle.0.is_null() {
            unsafe {
                let _ = CloseServiceHandle(self.handle);
            }
        }
    }
}

impl ServiceManager {
    /// Open a connection to the local Service Control Manager.
    pub fn open() -> Result<Self> {
        let handle = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .context("Failed to open Service Control Manager")?;

        Ok(Self { handle })
    }

    /// Open a specific service with query and start capabilities.
    pub fn open_service(&self, service_name: PCWSTR) -> Result<ServiceHandle> {
        let handle = unsafe {
            OpenServiceW(
                self.handle,
                service_name,
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START,
            )
        }
        .context("Failed to open service handle")?;

        Ok(ServiceHandle { handle })
    }
}

/// RAII handle wrapping an individual Windows service.
pub struct ServiceHandle {
    handle: SC_HANDLE,
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() && !self.handle.0.is_null() {
            unsafe {
                let _ = CloseServiceHandle(self.handle);
            }
        }
    }
}

impl ServiceHandle {
    /// Ensure the service is started and wait until it enters `SERVICE_RUNNING`.
    ///
    /// Returns the PID of the service process upon entering the running state.
    pub fn start_and_wait(&self, timeout: Duration) -> Result<u32> {
        let start_time = Instant::now();
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut bytes_needed = 0u32;

        loop {
            if start_time.elapsed() > timeout {
                return Err(anyhow!(
                    "Timed out waiting for service to reach running state"
                ));
            }

            let status_slice = unsafe {
                std::slice::from_raw_parts_mut(
                    ptr::from_mut::<SERVICE_STATUS_PROCESS>(&mut status).cast::<u8>(),
                    mem::size_of::<SERVICE_STATUS_PROCESS>(),
                )
            };

            unsafe {
                QueryServiceStatusEx(
                    self.handle,
                    SC_STATUS_PROCESS_INFO,
                    Some(status_slice),
                    &mut bytes_needed,
                )
            }
            .context("Failed to query service status")?;

            match status.dwCurrentState {
                SERVICE_STOPPED => {
                    let start_result = unsafe { StartServiceW(self.handle, None) };
                    if let Err(error) = start_result {
                        let win32_error = unsafe { GetLastError() };
                        if win32_error != ERROR_SERVICE_ALREADY_RUNNING {
                            return Err(anyhow!("Failed to start service: {error}"));
                        }
                    }
                    sleep(Duration::from_millis(100));
                }
                SERVICE_START_PENDING | SERVICE_STOP_PENDING => {
                    sleep(Duration::from_millis(250));
                }
                SERVICE_RUNNING => {
                    return Ok(status.dwProcessId);
                }
                _ => {
                    sleep(Duration::from_millis(250));
                }
            }
        }
    }
}
