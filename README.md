# privesc

Cross-platform privilege escalation for Rust. 

Run commands with elevated privileges on macOS, Linux, and Windows.

## Usage

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

## Platform Behavior

| Platform | GUI mode | CLI mode | Output capture |
|----------|----------|----------|----------------|
| macOS | AppleScript dialog | `sudo` | Yes |
| Linux | `pkexec` | `sudo` | Yes |
| Windows | UAC prompt | UAC prompt | No |

### macOS

GUI mode spawns an AppleScript authentication dialog via `osascript`. CLI mode uses `sudo` with optional custom prompt.

### Linux

GUI mode requires `pkexec` (PolicyKit). Falls back to error if unavailable. CLI mode uses `sudo`. Custom prompts only work in CLI mode due to pkexec limitations.

### Windows

Always shows UAC dialog regardless of `gui` parameter. Custom prompts are ignored (UAC controls the dialog). **stdout/stderr are not captured** — `PrivilegedOutput.stdout` and `.stderr` will be `None`.

## Security Considerations

This library executes commands with root/administrator privileges. Misuse can compromise system security.

**Input validation is your responsibility.** This library does not sanitize inputs. Before calling `Command::run()`:

- Validate `program` is an expected absolute path
- Validate all `args` against an allowlist if derived from user input
- Never pass unsanitized user input to `prompt`

**sudo prompt format strings**: The `prompt` parameter on Unix is passed to `sudo -p`, which interprets `%u`, `%h`, etc. Avoid user-controlled prompt strings or escape `%` characters.
