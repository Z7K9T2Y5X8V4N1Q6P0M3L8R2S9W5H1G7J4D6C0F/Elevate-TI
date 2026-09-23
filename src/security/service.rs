//! Windows Service Control Manager and Service handle management.
//!
//! Provides RAII handles for connecting to the SCM, querying service
//! states, and safely waiting for a service to reach running status.

use std::{
    mem, ptr,
    thread::sleep,
    time::{Duration, Instant},
};

use windows::{
    Win32::{
        Foundation::ERROR_SERVICE_ALREADY_RUNNING,
        System::Services::{
            CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_HANDLE,
            SC_MANAGER_CONNECT, SC_STATUS_PROCESS_INFO, SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS,
            SERVICE_RUNNING, SERVICE_START, SERVICE_START_PENDING, SERVICE_STATUS_PROCESS,
            SERVICE_STOP_PENDING, SERVICE_STOPPED, StartServiceW,
        },
    },
    core::PCWSTR,
};

use crate::error::ElevateError;

/// RAII handle wrapping an active Service Control Manager connection.
pub struct ServiceManager {
    handle: SC_HANDLE,
}

impl Drop for ServiceManager {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.handle);
            }
        }
    }
}

impl ServiceManager {
    /// Open a connection to the local Service Control Manager.
    pub fn open() -> Result<Self, ElevateError> {
        let handle = unsafe { OpenSCManagerW(PCWSTR::null(), PCWSTR::null(), SC_MANAGER_CONNECT) }
            .map_err(|source| ElevateError::Win32 {
                operation: "OpenSCManagerW",
                source,
            })?;

        Ok(Self { handle })
    }

    /// Open a specific service with query and start capabilities.
    pub fn open_service(&self, service_name: PCWSTR) -> Result<ServiceHandle, ElevateError> {
        let handle = unsafe {
            OpenServiceW(
                self.handle,
                service_name,
                SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START,
            )
        }
        .map_err(|source| ElevateError::Win32 {
            operation: "OpenServiceW",
            source,
        })?;

        Ok(ServiceHandle { handle })
    }
}

/// RAII handle wrapping an individual Windows service.
pub struct ServiceHandle {
    handle: SC_HANDLE,
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
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
    pub fn start_and_wait(&self, timeout: Duration) -> Result<u32, ElevateError> {
        let start_time = Instant::now();
        let mut status = SERVICE_STATUS_PROCESS::default();
        let mut bytes_needed = 0u32;

        loop {
            if start_time.elapsed() > timeout {
                return Err(ElevateError::ServiceWaitTimeout {
                    service_name: "TrustedInstaller".to_string(),
                    elapsed_seconds: timeout.as_secs(),
                });
            }

            let status_slice = unsafe {
                std::slice::from_raw_parts_mut(
                    ptr::from_mut(&mut status).cast(),
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
            .map_err(|source| ElevateError::Win32 {
                operation: "QueryServiceStatusEx",
                source,
            })?;

            match status.dwCurrentState {
                SERVICE_STOPPED => {
                    let start_result = unsafe { StartServiceW(self.handle, None) };
                    if let Err(service_error) = start_result {
                        if service_error.code() != ERROR_SERVICE_ALREADY_RUNNING.to_hresult() {
                            return Err(ElevateError::Win32 {
                                operation: "StartServiceW",
                                source: service_error,
                            });
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
