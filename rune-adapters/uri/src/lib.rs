use rune_core::models::{Algorithm, OtpAccount, OtpType};
use rune_core::source::{AdapterError, Source};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use url::Url;

/// Adapter for reading `otpauth://` URIs from an individual URI or collection file.
#[derive(Debug, Clone)]
pub struct UriSource {
    id: String,
    name: String,
    path: Option<PathBuf>,
    raw_content: Option<String>,
}

impl UriSource {
    /// Create a source from a file path pointing to a collection of URIs or a single URI.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Self {
        let p = path.as_ref().to_path_buf();
        let name = p
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("URI Source")
            .to_string();
        Self {
            id: format!("uri:{}", p.display()),
            name,
            path: Some(p),
            raw_content: None,
        }
    }

    /// Create a source directly from raw text content (single or multiple lines).
    pub fn from_content(content: impl Into<String>) -> Self {
        Self {
            id: "uri:memory".to_string(),
            name: "URI Collection (Memory)".to_string(),
            path: None,
            raw_content: Some(content.into()),
        }
    }

    /// Parse a single `otpauth://` URI into an `OtpAccount`.
    pub fn parse_uri(uri_str: &str) -> Result<OtpAccount, AdapterError> {
        let trimmed = uri_str.trim();
        if !trimmed.starts_with("otpauth://") {
            return Err(AdapterError::Format(format!(
                "Invalid URI scheme (must start with otpauth://): {trimmed}"
            )));
        }

        let parsed = Url::parse(trimmed)
            .map_err(|e| AdapterError::Format(format!("Failed to parse URL '{trimmed}': {e}")))?;

        let otp_type = match parsed.host_str() {
            Some("totp") => OtpType::Totp,
            Some("hotp") => OtpType::Hotp,
            Some(other) => {
                return Err(AdapterError::Format(format!(
                    "Unsupported OTP type in URI: {other}"
                )))
            }
            None => {
                return Err(AdapterError::Format(
                    "Missing OTP type (host) in URI".to_string(),
                ))
            }
        };

        // Extract path: /Issuer:Account or /Account
        let raw_path = parsed.path().trim_start_matches('/');
        let decoded_path = percent_encoding::percent_decode_str(raw_path)
            .decode_utf8_lossy()
            .to_string();

        let (mut path_issuer, path_account) = if let Some((iss, acc)) = decoded_path.split_once(':') {
            (Some(iss.trim().to_string()), acc.trim().to_string())
        } else {
            (None, decoded_path.trim().to_string())
        };

        // Query parameters
        let mut secret = None;
        let mut query_issuer = None;
        let mut algorithm = Algorithm::SHA1;
        let mut digits = 6u32;
        let mut period = 30u32;
        let mut counter = None;

        for (key, val) in parsed.query_pairs() {
            match key.to_ascii_lowercase().as_str() {
                "secret" => secret = Some(val.to_string()),
                "issuer" => query_issuer = Some(val.to_string()),
                "algorithm" => {
                    algorithm = Algorithm::from_str(&val)
                        .map_err(AdapterError::InvalidParameter)?;
                }
                "digits" => {
                    digits = val
                        .parse()
                        .map_err(|_| AdapterError::InvalidParameter(format!("Invalid digits: {val}")))?;
                }
                "period" => {
                    period = val
                        .parse()
                        .map_err(|_| AdapterError::InvalidParameter(format!("Invalid period: {val}")))?;
                }
                "counter" => {
                    counter = Some(val.parse().map_err(|_| {
                        AdapterError::InvalidParameter(format!("Invalid counter: {val}"))
                    })?);
                }
                _ => {} // Ignore unknown query keys
            }
        }

        let secret = secret.ok_or_else(|| {
            AdapterError::Format("Missing 'secret' parameter in otpauth URI".to_string())
        })?;

        // Prefer query issuer if set, otherwise path issuer
        let final_issuer = query_issuer.or(path_issuer.take());

        let account_name = if path_account.is_empty() {
            "Unnamed Account".to_string()
        } else {
            path_account
        };

        // Deterministic ID generation based on URI string or parameters
        let id = format!(
            "uri-{:016x}",
            blake3::hash(trimmed.as_bytes()).as_bytes()[..8]
                .iter()
                .fold(0u64, |acc, &b| (acc << 8) | (b as u64))
        );

        Ok(OtpAccount {
            id,
            name: account_name,
            issuer: final_issuer,
            secret,
            algorithm,
            digits,
            period,
            otp_type,
            counter,
            icon: None,
            note: None,
        })
    }

    /// Parse multiline text content into a vector of accounts.
    pub fn parse_collection(content: &str) -> Result<Vec<OtpAccount>, AdapterError> {
        let mut accounts = Vec::new();
        for (line_idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }

            if trimmed.starts_with("otpauth://") {
                match Self::parse_uri(trimmed) {
                    Ok(acc) => accounts.push(acc),
                    Err(e) => eprintln!("Warning: Failed to parse line {}: {}", line_idx + 1, e),
                }
            }
        }
        Ok(accounts)
    }
}

impl Source for UriSource {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn load(&self) -> Result<Vec<OtpAccount>, AdapterError> {
        if let Some(content) = &self.raw_content {
            return Self::parse_collection(content);
        }

        if let Some(path) = &self.path {
            if !path.exists() {
                return Err(AdapterError::NotFound(path.display().to_string()));
            }
            let text = fs::read_to_string(path)?;
            return Self::parse_collection(&text);
        }

        Ok(Vec::new())
    }
}

// Minimal inline blake3 hash helper so we don't need full blake3 crate if not desired,
// or we can use a standard hasher. Let's make a simple hash module here:
mod blake3 {
    pub struct Hash([u8; 8]);
    impl Hash {
        pub fn as_bytes(&self) -> &[u8; 8] {
            &self.0
        }
    }
    pub fn hash(bytes: &[u8]) -> Hash {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::Hasher;
        let mut h = DefaultHasher::new();
        h.write(bytes);
        Hash(h.finish().to_be_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_totp_uri() {
        let uri = "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30";
        let account = UriSource::parse_uri(uri).unwrap();

        assert_eq!(account.name, "alice");
        assert_eq!(account.issuer, Some("GitHub".to_string()));
        assert_eq!(account.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(account.digits, 6);
        assert_eq!(account.period, 30);
        assert_eq!(account.algorithm, Algorithm::SHA1);
        assert_eq!(account.otp_type, OtpType::Totp);
    }

    #[test]
    fn test_parse_collection() {
        let content = r#"
        # My 2FA Tokens
        otpauth://totp/Google:bob@gmail.com?secret=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&issuer=Google
        
        # Another one
        otpauth://totp/Cloudflare:ops?secret=GEZDGNBVGY3TQOJQ&issuer=Cloudflare&algorithm=SHA256&digits=8
        "#;

        let accounts = UriSource::parse_collection(content).unwrap();
        assert_eq!(accounts.len(), 2);
        assert_eq!(accounts[0].issuer, Some("Google".to_string()));
        assert_eq!(accounts[1].digits, 8);
        assert_eq!(accounts[1].algorithm, Algorithm::SHA256);
    }
}
