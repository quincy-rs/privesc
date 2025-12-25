mod error;

#[cfg(target_os = "macos")]
mod privesc_darwin;
#[cfg(target_os = "linux")]
mod privesc_linux;
#[cfg(windows)]
mod privesc_windows;

use std::{path::PathBuf, process::ExitStatus};

pub use crate::error::{PrivescError, Result};

#[cfg(target_os = "macos")]
use privesc_darwin::PrivilegedChildInner;
#[cfg(target_os = "linux")]
use privesc_linux::PrivilegedChildInner;
#[cfg(windows)]
use privesc_windows::PrivilegedChildInner;

/// Handle to a spawned privileged process.
///
/// This struct wraps the underlying platform-specific process handle and provides
/// methods to wait for completion and retrieve the output.
///
/// # Platform Behavior
/// - **macOS/Linux**: Wraps a `std::process::Child`.
/// - **Windows**: Wraps a Windows process `HANDLE`.
pub struct PrivilegedChild {
    inner: PrivilegedChildInner,
}

impl PrivilegedChild {
    /// Waits for the process to exit and returns the output.
    ///
    /// This method consumes the `PrivilegedChild` and blocks until the process
    /// has finished executing.
    ///
    /// # Note
    /// On Windows, stdout and stderr are always `None` as `ShellExecuteExW`
    /// does not support output redirection.
    pub fn wait(self) -> Result<PrivilegedOutput> {
        self.inner.wait()
    }

    /// Attempts to collect the exit status of the child if it has already exited.
    ///
    /// This method will not block. Returns `Ok(None)` if the process has not
    /// yet exited.
    ///
    /// Note: Unlike [`wait`](Self::wait), this method cannot return stdout/stderr
    /// because the process may still be running. To get output, use [`wait`](Self::wait).
    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>> {
        self.inner.try_wait()
    }

    /// Returns the OS-assigned process identifier of the child process, if available.
    ///
    /// # Platform Behavior
    /// - **macOS/Linux**: Returns `Some(pid)`.
    /// - **Windows**: Returns `None` (ShellExecuteExW doesn't provide the process ID).
    pub fn id(&self) -> Option<u32> {
        self.inner.id()
    }
}

/// Output from a privileged command execution.
///
/// Unlike `std::process::Output`, this struct uses `Option` for stdout/stderr
/// to accurately represent platforms where output capture is not possible
/// (e.g., Windows UAC elevation via `ShellExecuteExW`).
#[derive(Debug, Clone)]
pub struct PrivilegedOutput {
    /// The exit status of the process.
    pub status: ExitStatus,
    /// The captured stdout, if available.
    ///
    /// This is `None` on Windows, where `ShellExecuteExW` does not support
    /// output redirection.
    pub stdout: Option<Vec<u8>>,
    /// The captured stderr, if available.
    ///
    /// This is `None` on Windows, where `ShellExecuteExW` does not support
    /// output redirection.
    pub stderr: Option<Vec<u8>>,
}

impl PrivilegedOutput {
    /// Returns true if the process exited successfully.
    pub fn success(&self) -> bool {
        self.status.success()
    }

    /// Returns stdout as a UTF-8 string, if available and valid.
    pub fn stdout_str(&self) -> Option<&str> {
        self.stdout
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
    }

    /// Returns stderr as a UTF-8 string, if available and valid.
    pub fn stderr_str(&self) -> Option<&str> {
        self.stderr
            .as_ref()
            .and_then(|b| std::str::from_utf8(b).ok())
    }
}

/// Builder for executing a program with elevated privileges.
///
/// # Example
///
/// ```no_run
/// use privesc::PrivilegedCommand;
///
/// let output = PrivilegedCommand::new("/usr/bin/cat")
///     .arg("/etc/shadow")
///     .run()?;
/// # Ok::<(), privesc::PrivescError>(())
/// ```
///
/// # Platform Behavior
/// - **macOS**: Uses `osascript` with AppleScript for GUI, `sudo` for CLI.
/// - **Linux**: Uses `pkexec` for GUI, `sudo` for CLI.
/// - **Windows**: Uses `ShellExecuteExW` with "runas" verb (UAC). Output capture
///   is not available.
#[derive(Debug, Clone)]
pub struct PrivilegedCommand {
    program: PathBuf,
    args: Vec<String>,
    gui: bool,
    prompt: Option<String>,
}

impl PrivilegedCommand {
    /// Creates a new `Command` for the given program.
    ///
    /// # Arguments
    /// * `program` - The path to the program to execute with elevated privileges.
    pub fn new(program: impl Into<PathBuf>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            gui: false,
            prompt: None,
        }
    }

    /// Adds a single argument to pass to the program.
    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    /// Adds multiple arguments to pass to the program.
    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args.extend(args.into_iter().map(Into::into));
        self
    }

    /// Sets whether to use a GUI prompt for authentication.
    ///
    /// - `true`: Use GUI prompt (AppleScript on macOS, pkexec on Linux, UAC on Windows)
    /// - `false`: Use terminal-based sudo (default)
    ///
    /// On Windows, this parameter is ignored as only UAC elevation is available.
    pub fn gui(mut self, gui: bool) -> Self {
        self.gui = gui;
        self
    }

    /// Sets a custom prompt message for authentication.
    ///
    /// On Windows, this is ignored as UAC displays its own prompt.
    /// On Linux with GUI mode, this is ignored due to pkexec limitations.
    pub fn prompt(mut self, prompt: impl Into<String>) -> Self {
        self.prompt = Some(prompt.into());
        self
    }

    /// Executes the command with elevated privileges.
    ///
    /// # Returns
    /// A `PrivilegedOutput` containing the exit status and optionally captured
    /// stdout/stderr. Note that stdout/stderr are `None` on Windows.
    pub fn run(&self) -> Result<PrivilegedOutput> {
        if !self.program.is_absolute() {
            return Err(PrivescError::InvalidProgramPath(self.program.clone()));
        }

        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        let prompt = self.prompt.as_deref();

        #[cfg(target_os = "macos")]
        {
            privesc_darwin::run(&self.program, &args, self.gui, prompt)
        }
        #[cfg(windows)]
        {
            privesc_windows::run(&self.program, &args, self.gui, prompt)
        }
        #[cfg(target_os = "linux")]
        {
            privesc_linux::run(&self.program, &args, self.gui, prompt)
        }
    }

    /// Spawns the command with elevated privileges, returning a handle to the process.
    ///
    /// Unlike [`run`](Self::run), this method returns immediately after spawning,
    /// allowing you to perform other work while the privileged process runs.
    ///
    /// # Returns
    /// A `PrivilegedChild` handle that can be used to wait for the process to finish.
    ///
    /// # Platform Behavior
    /// - **macOS/Linux**: Returns a handle wrapping the underlying process.
    /// - **Windows**: Returns a handle wrapping the Windows process `HANDLE`.
    ///
    /// # Example
    /// ```no_run
    /// use privesc::PrivilegedCommand;
    ///
    /// let child = PrivilegedCommand::new("/usr/bin/long-running-task")
    ///     .spawn()?;
    ///
    /// // Do other work...
    ///
    /// let output = child.wait()?;
    /// # Ok::<(), privesc::PrivescError>(())
    /// ```
    pub fn spawn(&self) -> Result<PrivilegedChild> {
        if !self.program.is_absolute() {
            return Err(PrivescError::InvalidProgramPath(self.program.clone()));
        }

        let args: Vec<&str> = self.args.iter().map(String::as_str).collect();
        let prompt = self.prompt.as_deref();

        #[cfg(target_os = "macos")]
        let inner = privesc_darwin::spawn(&self.program, &args, self.gui, prompt)?;
        #[cfg(windows)]
        let inner = privesc_windows::spawn(&self.program, &args, self.gui, prompt)?;
        #[cfg(target_os = "linux")]
        let inner = privesc_linux::spawn(&self.program, &args, self.gui, prompt)?;

        Ok(PrivilegedChild { inner })
    }
}
