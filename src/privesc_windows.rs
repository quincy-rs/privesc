use std::os::windows::process::ExitStatusExt;
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

/// Escapes a single argument for Windows command-line parsing.
///
/// Follows the escaping rules for `CommandLineToArgvW`:
/// - Arguments containing spaces, tabs, or quotes are wrapped in double quotes
/// - Backslashes are literal unless followed by a double quote
/// - Backslashes preceding a double quote must be doubled
/// - Double quotes within the argument are escaped as `\"`
fn escape_argument(arg: &str) -> String {
    // Check if quoting is needed
    let needs_quoting = arg.is_empty()
        || arg.contains(' ')
        || arg.contains('\t')
        || arg.contains('"')
        || arg.contains('\\');

    if !needs_quoting {
        return arg.to_string();
    }

    let mut result = String::with_capacity(arg.len() + 2);
    result.push('"');

    let mut backslash_count = 0;

    for c in arg.chars() {
        match c {
            '\\' => {
                backslash_count += 1;
            }
            '"' => {
                // Double all backslashes before a quote, then add escaped quote
                for _ in 0..backslash_count {
                    result.push('\\');
                }
                backslash_count = 0;
                result.push('\\');
                result.push('"');
            }
            _ => {
                // Flush backslashes as-is (they're literal when not before a quote)
                for _ in 0..backslash_count {
                    result.push('\\');
                }
                backslash_count = 0;
                result.push(c);
            }
        }
    }

    // Double any trailing backslashes (they precede the closing quote)
    for _ in 0..backslash_count {
        result.push('\\');
        result.push('\\');
    }

    result.push('"');
    result
}

/// Escapes and joins arguments into a single command-line string.
fn escape_arguments(args: &[&str]) -> String {
    args.iter()
        .map(|arg| escape_argument(arg))
        .collect::<Vec<_>>()
        .join(" ")
}

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
fn spawn_gui(program: &str, args: &[&str]) -> Result<PrivilegedChildInner> {
    let verb = HSTRING::from("runas");
    let file = HSTRING::from(program);
    let parameters = HSTRING::from(escape_arguments(args));

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
    program: &str,
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
    program: &str,
    args: &[&str],
    gui: bool,
    prompt: Option<&str>,
) -> Result<PrivilegedOutput> {
    spawn(program, args, gui, prompt)?.wait()
}
