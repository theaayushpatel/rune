use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

/// Supported hashing algorithms for HMAC calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "UPPERCASE")]
pub enum Algorithm {
    #[default]
    SHA1,
    SHA256,
    SHA512,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::SHA1 => write!(f, "SHA1"),
            Algorithm::SHA256 => write!(f, "SHA256"),
            Algorithm::SHA512 => write!(f, "SHA512"),
        }
    }
}

impl FromStr for Algorithm {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_uppercase().as_str() {
            "SHA1" | "SHA-1" => Ok(Algorithm::SHA1),
            "SHA256" | "SHA-256" => Ok(Algorithm::SHA256),
            "SHA512" | "SHA-512" => Ok(Algorithm::SHA512),
            other => Err(format!("Unsupported algorithm: {other}")),
        }
    }
}

/// OTP token generation type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OtpType {
    #[default]
    Totp,
    Hotp,
}

impl fmt::Display for OtpType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OtpType::Totp => write!(f, "totp"),
            OtpType::Hotp => write!(f, "hotp"),
        }
    }
}

impl FromStr for OtpType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "totp" => Ok(OtpType::Totp),
            "hotp" => Ok(OtpType::Hotp),
            other => Err(format!("Unsupported OTP type: {other}")),
        }
    }
}

/// Common in-memory representation of an OTP account.
///
/// Regardless of whether the entry was imported from Aegis, KeePassXC,
/// an `otpauth://` URI, or another source, it is mapped into this unified struct.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OtpAccount {
    /// Unique identifier across the runtime (e.g. UUID or hash)
    pub id: String,
    /// Account label/username (e.g. user@example.com)
    pub name: String,
    /// Service/issuer (e.g. GitHub, Google, AWS)
    pub issuer: Option<String>,
    /// Base32 encoded secret key
    pub secret: String,
    /// Hashing algorithm (SHA1, SHA256, SHA512)
    pub algorithm: Algorithm,
    /// Number of output digits (typically 6, 7, or 8)
    pub digits: u32,
    /// Time step in seconds for TOTP (typically 30)
    pub period: u32,
    /// OTP flavor (TOTP or HOTP)
    pub otp_type: OtpType,
    /// Counter value for HOTP
    pub counter: Option<u64>,
    /// Optional icon indicator or tag
    pub icon: Option<String>,
    /// Optional note or description
    pub note: Option<String>,
}

impl OtpAccount {
    /// Clean display label formatted as "[Issuer] Name" or "Name".
    pub fn display_label(&self) -> String {
        match &self.issuer {
            Some(iss) if !iss.is_empty() => format!("{iss} ({})", self.name),
            _ => self.name.clone(),
        }
    }

    /// Primary issuer name or fallback to "Unknown".
    pub fn issuer_name(&self) -> &str {
        self.issuer.as_deref().unwrap_or("Unknown")
    }

    /// Calculate seconds remaining in the current period for a given unix timestamp.
    pub fn remaining_seconds(&self, timestamp: u64) -> u32 {
        if self.period == 0 {
            return 0;
        }
        let step = (timestamp % (self.period as u64)) as u32;
        self.period - step
    }

    /// Progress ratio of the current period elapsed (0.0 at start, 1.0 when expired).
    pub fn progress_ratio(&self, timestamp: u64) -> f64 {
        if self.period == 0 {
            return 1.0;
        }
        let elapsed = (timestamp % (self.period as u64)) as f64;
        elapsed / (self.period as f64)
    }
}
