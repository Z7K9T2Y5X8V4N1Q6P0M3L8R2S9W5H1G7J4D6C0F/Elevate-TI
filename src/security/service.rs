//! Windows Service Control Manager connection and service polling.

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
            SERVICE_RUNNING, SERVICE_START, SERVICE_STATUS_PROCESS, StartServiceW,
        },
    },
    core::PCWSTR,
};

use super::win32;
use crate::error::ElevateError;

/// Aligned stack storage matching the byte layout and alignment of `SERVICE_STATUS_PROCESS`.
#[repr(C, align(8))]
struct AlignedStatusBuffer([u8; mem::size_of::<SERVICE_STATUS_PROCESS>()]);

/// Safe RAII wrapper for Service Control Manager connection.
pub struct ServiceManager(SC_HANDLE);

impl Drop for ServiceManager {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

impl ServiceManager {
    /// Open a connection to the local Service Control Manager.
    pub fn open() -> Result<Self, ElevateError> {
        let handle = win32!(OpenSCManagerW(
            PCWSTR::null(),
            PCWSTR::null(),
            SC_MANAGER_CONNECT
        ))?;
        Ok(Self(handle))
    }

    /// Open an individual service with query and start rights.
    pub fn service(&self, name: PCWSTR) -> Result<Service, ElevateError> {
        let handle = win32!(OpenServiceW(
            self.0,
            name,
            SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_START,
        ))?;
        Ok(Service(handle))
    }
}

/// Safe RAII handle for an individual Windows service.
pub struct Service(SC_HANDLE);

impl Drop for Service {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseServiceHandle(self.0);
            }
        }
    }
}

impl Service {
    /// Ensure the service is running and wait until it enters `SERVICE_RUNNING`, returning its PID.
    pub fn start_and_wait(&self, name: &str, timeout: Duration) -> Result<u32, ElevateError> {
        let start = Instant::now();

        loop {
            if start.elapsed() > timeout {
                return Err(ElevateError::ServiceTimeout {
                    name: name.to_string(),
                    seconds: start.elapsed().as_secs(),
                });
            }

            let mut raw_buf = AlignedStatusBuffer([0u8; mem::size_of::<SERVICE_STATUS_PROCESS>()]);
            let mut bytes_needed = 0u32;

            win32!(QueryServiceStatusEx(
                self.0,
                SC_STATUS_PROCESS_INFO,
                Some(&mut raw_buf.0),
                &raw mut bytes_needed,
            ))?;

            // SAFETY: SERVICE_STATUS_PROCESS is a plain data struct, buffer has identical size and alignment.
            let status =
                unsafe { ptr::read_unaligned(raw_buf.0.as_ptr().cast::<SERVICE_STATUS_PROCESS>()) };

            if status.dwCurrentState == SERVICE_RUNNING {
                return Ok(status.dwProcessId);
            }

            let _ = self.try_start();
            sleep(Duration::from_millis(200));
        }
    }

    fn try_start(&self) -> Result<(), ElevateError> {
        let res = win32!(StartServiceW(self.0, None));
        match res {
            Ok(()) => Ok(()),
            Err(ElevateError::Win32 { ref source, .. })
                if source.code() == ERROR_SERVICE_ALREADY_RUNNING.to_hresult() =>
            {
                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}
