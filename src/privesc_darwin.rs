use std::{
    io::Write,
    process::{Child, Command, ExitStatus, Stdio},
};

use crate::PrivilegedOutput;
use crate::error::Result;

const ESCALLATION_SCRIPT: &str = r#"
on run argv
    set toolPath to item 1 of argv
    set prompt to item 2 of argv
    set cmd to quoted form of toolPath
    repeat with i from 3 to (count of argv)
        set cmd to cmd & " " & (quoted form of (item i of argv))
    end repeat
    return do shell script cmd with administrator privileges with prompt prompt
end run
"#;

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

/// Spawn a program with elevated privileges using `osascript`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
/// - `prompt` - The prompt to display to the user.
///
/// # Returns:
/// - `Result<PrivilegedChildInner>` - A handle to the spawned process.
fn spawn_gui(program: &str, args: &[&str], prompt: Option<&str>) -> Result<PrivilegedChildInner> {
    let mut process = Command::new("osascript")
        .arg("-")
        .arg(program)
        .arg(prompt.unwrap_or(&format!(
            "Administrator privileges required to launch {program}",
        )))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    process
        .stdin
        .as_mut()
        .expect("stdin piped")
        .write_all(ESCALLATION_SCRIPT.as_bytes())?;

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
fn spawn_cli(program: &str, args: &[&str], prompt: Option<&str>) -> Result<PrivilegedChildInner> {
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

/// Spawn a program with elevated privileges using either `osascript` or `sudo`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
/// - `gui` - Whether to prompt the user for a password using GUI or sudo.
/// - `prompt` - The prompt to display to the user.
///
/// # Returns:
/// - `Result<PrivilegedChildInner>` - A handle to the spawned process.
pub fn spawn(
    program: &str,
    args: &[&str],
    gui: bool,
    prompt: Option<&str>,
) -> Result<PrivilegedChildInner> {
    if gui {
        spawn_gui(program, args, prompt)
    } else {
        spawn_cli(program, args, prompt)
    }
}

/// Execute a program with elevated privileges using either `osascript` or `sudo`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
/// - `gui` - Whether to prompt the user for a password using GUI or sudo.
/// - `prompt` - The prompt to display to the user.
///
/// # Returns:
/// - `Result<PrivilegedOutput>` - The output of the program.
pub fn run(
    program: &str,
    args: &[&str],
    gui: bool,
    prompt: Option<&str>,
) -> Result<PrivilegedOutput> {
    spawn(program, args, gui, prompt)?.wait()
}
