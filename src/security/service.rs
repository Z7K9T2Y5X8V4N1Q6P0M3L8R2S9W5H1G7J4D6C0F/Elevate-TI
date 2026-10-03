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

use super::macros::win32_call;
use crate::error::ElevateError;

/// The operational outcome of a single service state poll check.
enum ServicePollOutcome {
    /// Service is still transitioning; sleep for the specified duration and retry.
    ContinueWaiting(Duration),
    /// Service has reached `SERVICE_RUNNING` with the given process identifier.
    Running(u32),
}

/// RAII handle wrapping an active Service Control Manager connection.
pub struct ServiceManager {
    service_manager_handle: SC_HANDLE,
}

impl Drop for ServiceManager {
    fn drop(&mut self) {
        if !self.service_manager_handle.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.service_manager_handle);
            }
        }
    }
}

impl ServiceManager {
    /// Open a connection to the local Service Control Manager.
    pub fn open() -> Result<Self, ElevateError> {
        let service_manager_handle = win32_call!(OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT
        ))?;

        Ok(Self {
            service_manager_handle,
        })
    }

    /// Open a specific service with query and start capabilities.
    pub fn open_service(&self, service_name: PCWSTR) -> Result<ServiceHandle, ElevateError> {
        let service_handle = win32_call!(OpenServiceW(
            self.service_manager_handle,
            service_name,
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START,
        ))?;

        Ok(ServiceHandle { service_handle })
    }
}

/// RAII handle wrapping an individual Windows service.
pub struct ServiceHandle {
    service_handle: SC_HANDLE,
}

impl Drop for ServiceHandle {
    fn drop(&mut self) {
        if !self.service_handle.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.service_handle);
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

        loop {
            let elapsed_time = start_time.elapsed();
            if elapsed_time > timeout {
                return Err(ElevateError::ServiceWaitTimeout {
                    service_name: "TrustedInstaller".to_string(),
                    elapsed_seconds: elapsed_time.as_secs(),
                });
            }

            match self.poll_state()? {
                ServicePollOutcome::Running(process_id) => return Ok(process_id),
                ServicePollOutcome::ContinueWaiting(wait_duration) => sleep(wait_duration),
            }
        }
    }

    /// Query the current service status and respond accordingly.
    fn poll_state(&self) -> Result<ServicePollOutcome, ElevateError> {
        // Use an aligned stack buffer matching the exact byte layout of SERVICE_STATUS_PROCESS.
        #[repr(C, align(8))]
        struct AlignedServiceStatusBuffer {
            data: [u8; mem::size_of::<SERVICE_STATUS_PROCESS>()],
        }

        let mut aligned_buffer = AlignedServiceStatusBuffer {
            data: [0u8; mem::size_of::<SERVICE_STATUS_PROCESS>()],
        };
        let mut bytes_needed = 0u32;

        win32_call!(QueryServiceStatusEx(
            self.service_handle,
            SC_STATUS_PROCESS_INFO,
            Some(&mut aligned_buffer.data),
            &mut bytes_needed,
        ))?;

        // SAFETY: SERVICE_STATUS_PROCESS contains only plain integer and enum types (Plain Old Data),
        // the buffer matches its size and alignment, and has been populated by QueryServiceStatusEx.
        let status: SERVICE_STATUS_PROCESS = unsafe {
            ptr::read_unaligned(
                aligned_buffer
                    .data
                    .as_ptr()
                    .cast::<SERVICE_STATUS_PROCESS>(),
            )
        };

        match status.dwCurrentState {
            SERVICE_STOPPED => {
                self.trigger_start()?;
                Ok(ServicePollOutcome::ContinueWaiting(Duration::from_millis(
                    100,
                )))
            }
            SERVICE_START_PENDING | SERVICE_STOP_PENDING => Ok(
                ServicePollOutcome::ContinueWaiting(Duration::from_millis(250)),
            ),
            SERVICE_RUNNING => Ok(ServicePollOutcome::Running(status.dwProcessId)),
            _ => Ok(ServicePollOutcome::ContinueWaiting(Duration::from_millis(
                250,
            ))),
        }
    }

    /// Trigger service execution, ignoring the benign error if it was already running.
    fn trigger_start(&self) -> Result<(), ElevateError> {
        let invocation_result = win32_call!(StartServiceW(self.service_handle, None));
        match invocation_result {
            Ok(()) => Ok(()),
            Err(ElevateError::Win32 { ref source, .. })
                if source.code() == ERROR_SERVICE_ALREADY_RUNNING.to_hresult() =>
            {
                Ok(())
            }
            Err(unexpected_error) => Err(unexpected_error),
        }
    }
}
