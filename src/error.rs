use std::path::PathBuf;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum PrivescError {
    #[error("Invalid program path: {0}")]
    InvalidProgramPath(PathBuf),
    #[error("Failed to execute command with privileges: {0}")]
    PrivilegeEscalationFailed(String),
    #[error("Failed to execute command: {0}")]
    CommandExecutionFailed(#[from] std::io::Error),
    #[error("Privilege escalation tool not found: {0}")]
    PrivilegeEscalationToolNotFound(String),
}

pub type Result<T> = std::result::Result<T, PrivescError>;
