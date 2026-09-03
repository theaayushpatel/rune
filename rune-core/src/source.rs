use crate::models::OtpAccount;
use thiserror::Error;

/// Common errors that can occur during adapter source loading/decryption.
#[derive(Error, Debug)]
pub enum AdapterError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Format parsing error: {0}")]
    Format(String),
    #[error("Decryption error: {0}")]
    Decryption(String),
    #[error("Incorrect password or corrupt encryption key")]
    InvalidPassword,
    #[error("Missing password for encrypted source")]
    PasswordRequired,
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("Source not found: {0}")]
    NotFound(String),
}

/// The common interface that every source adapter must implement.
///
/// Rune acts as a runtime layer and never modifies source files.
/// Source files are read-only by default.
pub trait Source: Send + Sync {
    /// Unique identifier for this source (e.g. "aegis:vault.json")
    fn id(&self) -> &str;

    /// Human-readable descriptor of the source (e.g. "Aegis Backup")
    fn name(&self) -> &str;

    /// Load and transform entries into the unified `OtpAccount` representation.
    fn load(&self) -> Result<Vec<OtpAccount>, AdapterError>;
}
