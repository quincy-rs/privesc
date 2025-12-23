use std::{
    io::Write,
    process::{Command, Stdio},
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

/// Execute a program with elevated privileges using `osascript`.
///
/// # Args:
/// - `program` - The path to the program to execute.
/// - `args` - The arguments to pass to the program.
///
/// # Returns:
/// - `Result<PrivilegedOutput>` - The output of the program.
fn privesc_gui(program: &str, args: &[&str], prompt: Option<&str>) -> Result<PrivilegedOutput> {
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
pub fn privesc(
    program: &str,
    args: &[&str],
    gui: bool,
    prompt: Option<&str>,
) -> Result<PrivilegedOutput> {
    if gui {
        privesc_gui(program, args, prompt)
    } else {
        privesc_cli(program, args, prompt)
    }
}
