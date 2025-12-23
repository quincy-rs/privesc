use crate::PrivilegedOutput;
use crate::error::{PrivescError, Result};
use std::process::{Command, Stdio};

/// Execute a program with elevated privileges using `pkexec`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
///
/// # Returns:
/// - `Result<PrivilegedOutput>` - The output of the program.
fn privesc_gui(program: &str, args: &[&str]) -> Result<PrivilegedOutput> {
    if which::which("pkexec").is_err() {
        return Err(PrivescError::PrivilegeEscalationToolNotFound(
            "pkexec".to_string(),
        ));
    }

    let process = Command::new("pkexec")
        .arg(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let output = process.wait_with_output()?;
    Ok(PrivilegedOutput {
        status: output.status,
        stdout: Some(output.stdout),
        stderr: Some(output.stderr),
    })
}

/// Execute a program with elevated privileges using `sudo`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
/// - `prompt` - The prompt to display to the user.
///
/// # Returns:
/// - `Result<PrivilegedOutput>` - The output of the program.
fn privesc_cli(program: &str, args: &[&str], prompt: Option<&str>) -> Result<PrivilegedOutput> {
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

    let output = process.wait_with_output()?;
    Ok(PrivilegedOutput {
        status: output.status,
        stdout: Some(output.stdout),
        stderr: Some(output.stderr),
    })
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
pub fn privesc(
    program: &str,
    args: &[&str],
    gui: bool,
    prompt: Option<&str>,
) -> Result<PrivilegedOutput> {
    if gui {
        privesc_gui(program, args)
    } else {
        privesc_cli(program, args, prompt)
    }
}
