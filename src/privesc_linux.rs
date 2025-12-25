use crate::PrivilegedOutput;
use crate::error::{PrivescError, Result};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};

/// Platform-specific handle to a spawned privileged process.
///
/// This struct wraps the underlying process and provides methods to wait for
/// completion and retrieve the output.
pub struct PrivilegedChildInner {
    child: Child,
}

impl PrivilegedChildInner {
    /// Waits for the process to exit and returns the output.
    ///
    /// This method consumes the handle and blocks until the process
    /// has finished executing.
    pub fn wait(self) -> Result<PrivilegedOutput> {
        let output = self.child.wait_with_output()?;
        Ok(PrivilegedOutput {
            status: output.status,
            stdout: Some(output.stdout),
            stderr: Some(output.stderr),
        })
    }

    /// Attempts to collect the exit status of the child if it has already exited.
    ///
    /// This method will not block. Returns `Ok(None)` if the process has not
    /// yet exited.
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        Ok(self.child.try_wait()?)
    }

    /// Returns the OS-assigned process identifier of the child process, if available.
    pub fn id(&self) -> Option<u32> {
        Some(self.child.id())
    }
}

/// Spawn a program with elevated privileges using `pkexec`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
///
/// # Returns:
/// - `Result<PrivilegedChildInner>` - A handle to the spawned process.
fn spawn_gui(program: &Path, args: &[&str]) -> Result<PrivilegedChildInner> {
    let pkexec_path = which::which("pkexec")
        .map_err(|_| PrivescError::PrivilegeEscalationToolNotFound("pkexec".to_string()))?;

    let process = Command::new(pkexec_path)
        .arg(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    Ok(PrivilegedChildInner { child: process })
}

/// Spawn a program with elevated privileges using `sudo`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
/// - `prompt` - The prompt to display to the user.
///
/// # Returns:
/// - `Result<PrivilegedChildInner>` - A handle to the spawned process.
fn spawn_cli(program: &Path, args: &[&str], prompt: Option<&str>) -> Result<PrivilegedChildInner> {
    let mut command = Command::new("sudo");

    if let Some(prompt) = prompt {
        command.arg("-p").arg(prompt);
    }

    let process = command
        .arg("--")
        .arg(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    Ok(PrivilegedChildInner { child: process })
}

/// Spawn a program with elevated privileges using either `pkexec` or `sudo`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
/// - `gui` - Whether to prompt the user for a password using GUI or sudo.
/// - `prompt` - The prompt to display to the user. Only used if `gui` is false due to `pkexec` limitations.
///
/// # Returns:
/// - `Result<PrivilegedChildInner>` - A handle to the spawned process.
pub fn spawn(
    program: &Path,
    args: &[&str],
    gui: bool,
    prompt: Option<&str>,
) -> Result<PrivilegedChildInner> {
    if gui {
        spawn_gui(program, args)
    } else {
        spawn_cli(program, args, prompt)
    }
}

/// Execute a program with elevated privileges using either `pkexec` or `sudo`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
/// - `gui` - Whether to prompt the user for a password using GUI or sudo.
/// - `prompt` - The prompt to display to the user. Only used if `gui` is false due to `pkexec` limitations.
///
/// # Returns:
/// - `Result<PrivilegedOutput>` - The output of the program.
pub fn run(
    program: &Path,
    args: &[&str],
    gui: bool,
    prompt: Option<&str>,
) -> Result<PrivilegedOutput> {
    spawn(program, args, gui, prompt)?.wait()
}
