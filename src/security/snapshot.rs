//! Lightweight native Windows process snapshot iterator using `ToolHelp32`.

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, PROCESSENTRY32W, Process32FirstW, Process32NextW,
        TH32CS_SNAPPROCESS,
    },
};

use super::win32;
use crate::error::ElevateError;

/// Lightweight RAII iterator over active system processes.
pub struct ProcessSnapshot {
    handle: HANDLE,
    entry: PROCESSENTRY32W,
    started: bool,
}

impl Drop for ProcessSnapshot {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

impl ProcessSnapshot {
    /// Capture a new process snapshot of the current system state.
    pub fn new() -> Result<Self, ElevateError> {
        let handle = win32!(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0))?;
        let entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        Ok(Self {
            handle,
            entry,
            started: false,
        })
    }
}

impl Iterator for ProcessSnapshot {
    type Item = (u32, String);

    fn next(&mut self) -> Option<Self::Item> {
        let ok = if self.started {
            unsafe { Process32NextW(self.handle, &raw mut self.entry).is_ok() }
        } else {
            self.started = true;
            unsafe { Process32FirstW(self.handle, &raw mut self.entry).is_ok() }
        };

        if !ok {
            return None;
        }

        let len = self
            .entry
            .szExeFile
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.entry.szExeFile.len());
        let name = String::from_utf16_lossy(&self.entry.szExeFile[..len]);

        Some((self.entry.th32ProcessID, name))
    }
}
