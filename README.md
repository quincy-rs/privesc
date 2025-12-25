# privesc
[![Crates.io](https://img.shields.io/crates/v/privesc.svg)](https://crates.io/crates/privesc)
[![Documentation](https://docs.rs/privesc/badge.svg)](https://docs.rs/privesc/)
[![Build status](https://github.com/quincy-rs/privesc/workflows/CI/badge.svg)](https://github.com/quincy-rs/privesc/actions?query=workflow%3ACI)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENCE)
[![Matrix](https://img.shields.io/badge/chat-%23quincy:matrix.org-%2346BC99?logo=matrix)](https://matrix.to/#/#quincy:matrix.org)

Cross-platform privilege escalation for Rust. 

Run commands with elevated privileges on macOS, Linux, and Windows.

## Usage

**There is explicit validation for the `program` parameter to ensure that it is an absolute path to an executable file.**

This is done in order to ensure that the target executable has not been tampered with or is not a symlink to a malicious binary (PATH hijacking etc.)

```rust
use privesc::PrivilegedCommand;

fn main() -> privesc::Result<()> {
    let output = PrivilegedCommand::new("/usr/bin/cat")
        .arg("/etc/shadow")
        .run()?;

    if output.success() {
        if let Some(content) = output.stdout_str() {
            println!("{content}");
        }
    }

    Ok(())
}
```

With all options:

```rust
use privesc::PrivilegedCommand;

let output = PrivilegedCommand::new("/usr/bin/cat")
    .args(["/etc/shadow", "/etc/passwd"])
    .gui(true)
    .prompt("Reading protected files")
    .run()?;
```

### Spawning without blocking

Use `spawn()` to start a privileged process and continue working while it runs:

```rust
use privesc::PrivilegedCommand;

fn main() -> privesc::Result<()> {
    let mut child = PrivilegedCommand::new("/usr/bin/long-task")
        .spawn()?;

    if let Some(id) = child.id() {
        println!("Process started with ID: {id}");
    }

    // Do other work while the process runs...

    // Check if done without blocking
    if let Some(status) = child.try_wait()? {
        println!("Already finished: {status}");
    }

    // Block until completion
    let output = child.wait()?;
    println!("Exit status: {}", output.status);

    Ok(())
}
```

## Platform Behavior

| Platform | GUI mode | CLI mode | Output capture |
|----------|----------|----------|----------------|
| macOS | AppleScript dialog | `sudo` | Yes |
| Linux | `pkexec` | `sudo` | Yes |
| Windows | UAC prompt | UAC prompt | No |

### macOS

**CLI mode (`sudo`)**: Arguments are passed directly via Rust's `Command::args()`, which uses `execve` under the hood. No shell is involved — arguments are passed as-is to the target program regardless of special characters.

**GUI mode (`osascript`)**: Arguments flow through two stages:
1. Rust → osascript: Uses `Command::args()` (no shell, safe)
2. AppleScript → target: Uses `quoted form of` to escape each argument before passing to `do shell script`

AppleScript's `quoted form of` wraps arguments in single quotes and escapes embedded single quotes as `'\''`. This prevents shell interpretation of `$`, backticks, spaces, and other metacharacters.

### Linux

**CLI mode (`sudo`)**: Arguments are passed directly via Rust's `Command::args()`, which uses `execve` under the hood. No shell is involved — arguments are passed as-is to the target program regardless of special characters.

**GUI mode (`pkexec`)**: Same as CLI mode (`sudo`)

### Windows

**CLI mode (UAC via `ShellExecuteExW`)**: The Windows API takes arguments as a single string, not an array. This library implements custom escaping following Windows command-line parsing conventions:
- **Regular executables**: Arguments are escaped per `CommandLineToArgvW` rules (quotes, backslashes)
- **Batch files (`.bat`/`.cmd`)**: Additional escaping prevents `%VAR%` environment variable expansion and related injection vectors (addresses CVE-2024-24576 class vulnerabilities)

**GUI mode (`runas`)**: Same as CLI mode (`ShellExecuteExW`)
