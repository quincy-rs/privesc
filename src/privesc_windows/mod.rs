//! Windows privilege escalation implementation.
//!
//! This module provides functionality to spawn and run processes with elevated
//! privileges on Windows using `ShellExecuteExW` with the "runas" verb to trigger
//! UAC elevation.

mod args;

use std::os::windows::process::ExitStatusExt;
use std::path::Path;
use std::process::ExitStatus;

use windows::{
    Win32::{
        Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT},
        System::Threading::{GetExitCodeProcess, INFINITE, WaitForSingleObject},
        UI::Shell::{SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW, ShellExecuteExW},
    },
    core::{HSTRING, PCWSTR},
};

use crate::PrivilegedOutput;
use crate::error::{PrivescError, Result};

use args::{escape_arguments, escape_bat_arguments};

/// Platform-specific handle to a spawned privileged process.
///
/// This struct wraps the Windows process handle and provides methods to wait for
/// completion and retrieve the exit status.
///
/// # Note
/// On Windows, stdout and stderr capture is not available when using UAC elevation
/// via `ShellExecuteExW`. The [`wait`](Self::wait) method will always return `None`
/// for stdout and stderr.
pub struct PrivilegedChildInner {
    handle: HANDLE,
}

// SAFETY: Windows process handles are valid to use from any thread.
// All mutable access is protected by &mut self, preventing data races.
unsafe impl Send for PrivilegedChildInner {}
unsafe impl Sync for PrivilegedChildInner {}

impl PrivilegedChildInner {
    /// Waits for the process to exit and returns the output.
    ///
    /// This method consumes the handle and blocks until the process
    /// has finished executing.
    ///
    /// # Note
    /// On Windows, stdout and stderr are always `None` as `ShellExecuteExW`
    /// does not support output redirection.
    pub fn wait(self) -> Result<PrivilegedOutput> {
        // SAFETY: handle is valid as it was obtained from ShellExecuteExW.
        let wait_result = unsafe { WaitForSingleObject(self.handle, INFINITE) };

        if wait_result != WAIT_OBJECT_0 {
            // Don't close handle here - Drop will handle it
            return Err(PrivescError::PrivilegeEscalationFailed(
                "Failed to wait for process".to_string(),
            ));
        }

        let mut exit_code: u32 = 0;
        // SAFETY: handle is valid and exit_code is a valid pointer.
        let exit_code_result = unsafe { GetExitCodeProcess(self.handle, &mut exit_code) };

        if let Err(e) = exit_code_result {
            return Err(PrivescError::PrivilegeEscalationFailed(format!(
                "Failed to get exit code: {}",
                e
            )));
        }

        Ok(PrivilegedOutput {
            status: ExitStatus::from_raw(exit_code),
            stdout: None,
            stderr: None,
        })
    }

    /// Attempts to collect the exit status of the child if it has already exited.
    ///
    /// This method will not block. Returns `Ok(None)` if the process has not
    /// yet exited.
    ///
    /// # Note
    /// On Windows, this only returns the exit status, not the full output.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        // SAFETY: handle is valid.
        let wait_result = unsafe { WaitForSingleObject(self.handle, 0) };

        if wait_result == WAIT_TIMEOUT {
            return Ok(None);
        }

        if wait_result != WAIT_OBJECT_0 {
            return Err(PrivescError::PrivilegeEscalationFailed(
                "Failed to check process status".to_string(),
            ));
        }

        let mut exit_code: u32 = 0;
        // SAFETY: handle is valid and exit_code is a valid pointer.
        let exit_code_result = unsafe { GetExitCodeProcess(self.handle, &mut exit_code) };

        if let Err(e) = exit_code_result {
            return Err(PrivescError::PrivilegeEscalationFailed(format!(
                "Failed to get exit code: {}",
                e
            )));
        }

        Ok(Some(ExitStatus::from_raw(exit_code)))
    }

    /// Returns the OS-assigned process identifier of the child process, if available.
    ///
    /// On Windows, this always returns `None` as `ShellExecuteExW` does not provide
    /// the process ID directly.
    pub fn id(&self) -> Option<u32> {
        None
    }
}

impl Drop for PrivilegedChildInner {
    fn drop(&mut self) {
        // SAFETY: handle is valid.
        let _ = unsafe { CloseHandle(self.handle) };
    }
}

/// Returns true if the given path has a batch file extension (.bat or .cmd).
fn is_batch_file(path: &Path) -> bool {
    path.extension()
        .and_then(|ext| ext.to_str())
        .is_some_and(|ext| ext.eq_ignore_ascii_case("bat") || ext.eq_ignore_ascii_case("cmd"))
}

/// Spawn a program with elevated privileges using `ShellExecuteExW` with the "runas" verb.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
///
/// # Returns:
/// - `Result<PrivilegedChildInner>` - A handle to the spawned process.
///
/// # Note:
/// This function uses `ShellExecuteExW` with the "runas" verb to trigger UAC elevation.
/// stdout and stderr capture is not available.
///
/// Batch files (.bat, .cmd) are handled with special escaping rules to prevent
/// command injection via environment variable expansion.
fn spawn_gui(program: &Path, args: &[&str]) -> Result<PrivilegedChildInner> {
    let verb = HSTRING::from("runas");
    let file = HSTRING::from(program);

    // Use batch-specific escaping for .bat/.cmd files
    let parameters = if is_batch_file(program) {
        HSTRING::from(escape_bat_arguments(args))
    } else {
        HSTRING::from(escape_arguments(args))
    };

    let mut info = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb.as_ptr()),
        lpFile: PCWSTR(file.as_ptr()),
        lpParameters: PCWSTR(parameters.as_ptr()),
        nShow: windows::Win32::UI::WindowsAndMessaging::SW_HIDE.0,
        ..Default::default()
    };

    // SAFETY: info is properly initialized and the HSTRING references remain valid
    // for the duration of the call.
    let result = unsafe { ShellExecuteExW(&mut info) };

    if let Err(e) = result {
        return Err(PrivescError::PrivilegeEscalationFailed(format!(
            "ShellExecuteExW failed: {}",
            e
        )));
    }

    let handle = info.hProcess;

    if handle.is_invalid() {
        return Err(PrivescError::PrivilegeEscalationFailed(
            "Failed to get process handle".to_string(),
        ));
    }

    Ok(PrivilegedChildInner { handle })
}

/// Spawn a program with elevated privileges using `ShellExecuteExW`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
/// - `gui` - Ignored on Windows, as only GUI elevation via UAC is supported.
/// - `prompt` - Ignored on Windows, as UAC displays its own prompt.
///
/// # Returns:
/// - `Result<PrivilegedChildInner>` - A handle to the spawned process.
///
/// # Note:
/// stdout and stderr capture is not available on Windows with UAC elevation.
pub fn spawn(
    program: &Path,
    args: &[&str],
    _gui: bool,
    _prompt: Option<&str>,
) -> Result<PrivilegedChildInner> {
    spawn_gui(program, args)
}

/// Execute a program with elevated privileges using `ShellExecuteExW`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
/// - `gui` - Ignored on Windows, as only GUI elevation via UAC is supported.
/// - `prompt` - Ignored on Windows, as UAC displays its own prompt.
///
/// # Returns:
/// - `Result<PrivilegedOutput>` - The output of the program.
///
/// # Note:
/// stdout and stderr are `None` as `ShellExecuteExW` does not support output redirection.
pub fn run(
    program: &Path,
    args: &[&str],
    gui: bool,
    prompt: Option<&str>,
) -> Result<PrivilegedOutput> {
    spawn(program, args, gui, prompt)?.wait()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_batch_file() {
        // Batch files should be detected
        assert!(is_batch_file(Path::new("script.bat")));
        assert!(is_batch_file(Path::new("script.cmd")));
        assert!(is_batch_file(Path::new(r"C:\Windows\script.bat")));
        assert!(is_batch_file(Path::new(r"C:\Windows\script.cmd")));

        // Case-insensitive detection
        assert!(is_batch_file(Path::new("script.BAT")));
        assert!(is_batch_file(Path::new("script.CMD")));
        assert!(is_batch_file(Path::new("script.Bat")));
        assert!(is_batch_file(Path::new("script.Cmd")));

        // Non-batch files should not be detected
        assert!(!is_batch_file(Path::new("program.exe")));
        assert!(!is_batch_file(Path::new("script.ps1")));
        assert!(!is_batch_file(Path::new("script.sh")));
        assert!(!is_batch_file(Path::new(r"C:\Windows\System32\cmd.exe")));
        assert!(!is_batch_file(Path::new("nobatch")));
        assert!(!is_batch_file(Path::new("")));

        // Edge cases: .bat/.cmd in the filename but not as extension
        assert!(!is_batch_file(Path::new("batch.bat.exe")));
        assert!(!is_batch_file(Path::new("cmd.cmd.txt")));
    }
}
