pub mod crypto;
pub mod schema;

use crypto::decrypt_2fas_payload;
use rune_core::models::{Algorithm, OtpAccount, OtpType};
use rune_core::source::{AdapterError, Source};
use schema::{TwoFasPayload, TwoFasService};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Find the latest 2FAS backup file in a directory.
/// Scans for `.2fas` and `.json` files and picks the newest backup based on modification time and filename.
pub fn find_latest_2fas_backup(dir: &Path) -> Result<PathBuf, AdapterError> {
    if !dir.is_dir() {
        return Err(AdapterError::NotFound(format!(
            "{} is not a directory",
            dir.display()
        )));
    }

    let mut candidates = Vec::new();
    let entries = fs::read_dir(dir).map_err(AdapterError::Io)?;

    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_file() {
            let is_candidate = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("2fas") || e.eq_ignore_ascii_case("json"))
                .unwrap_or(false);

            if is_candidate {
                let mtime = entry
                    .metadata()
                    .and_then(|m| m.modified())
                    .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("")
                    .to_string();
                candidates.push((mtime, name, path));
            }
        }
    }

    if candidates.is_empty() {
        return Err(AdapterError::NotFound(format!(
            "No 2FAS backup files (.2fas or .json) found in directory: {}",
            dir.display()
        )));
    }

    // Sort: newest mtime first, then lexicographically descending filename
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

    Ok(candidates[0].2.clone())
}

/// Source adapter for reading 2FAS Authenticator backup files (.2fas / .json) or backup directories.
#[derive(Debug, Clone)]
pub struct TwoFasSource {
    id: String,
    name: String,
    path: Option<PathBuf>,
    raw_content: Option<String>,
    password: Option<String>,
}

impl TwoFasSource {
    /// Create a source from a file or folder path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Self {
        let p = path.as_ref().to_path_buf();
        let name = p
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("2FAS Backup")
            .to_string();
        Self {
            id: format!("2fas:{}", p.display()),
            name,
            path: Some(p),
            raw_content: None,
            password: None,
        }
    }

    /// Create a source pointing to a 2FAS backup folder (auto-detects the latest backup file).
    pub fn from_dir<P: AsRef<Path>>(dir: P) -> Self {
        Self::from_file(dir)
    }

    /// Create a source directly from JSON content in memory.
    pub fn from_json_str(content: impl Into<String>) -> Self {
        Self {
            id: "2fas:memory".to_string(),
            name: "2FAS Backup (Memory)".to_string(),
            path: None,
            raw_content: Some(content.into()),
            password: None,
        }
    }

    /// Set the decryption password for an encrypted backup.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// If this source points to a directory, dynamically resolve the newest backup file.
    /// Otherwise returns the configured file path.
    pub fn resolve_file(&self) -> Result<PathBuf, AdapterError> {
        if let Some(path) = &self.path {
            if path.is_dir() {
                find_latest_2fas_backup(path)
            } else if path.exists() {
                Ok(path.clone())
            } else {
                Err(AdapterError::NotFound(path.display().to_string()))
            }
        } else {
            Err(AdapterError::Format("No content or path provided".to_string()))
        }
    }

    /// Check whether this 2FAS backup (or the latest backup in the folder) is encrypted.
    pub fn is_encrypted(&self) -> Result<bool, AdapterError> {
        let (raw_json, _) = self.get_content()?;
        let payload: TwoFasPayload = serde_json::from_str(&raw_json)
            .map_err(|e| AdapterError::Format(format!("Invalid 2FAS JSON: {e}")))?;

        match payload {
            TwoFasPayload::Object(backup) => {
                let has_encrypted_services = backup
                    .services_encrypted
                    .as_deref()
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                let has_reference = backup
                    .reference
                    .as_deref()
                    .map(|s| !s.trim().is_empty())
                    .unwrap_or(false);
                Ok(has_encrypted_services || has_reference)
            }
            TwoFasPayload::List(_) => Ok(false),
        }
    }

    fn get_content(&self) -> Result<(String, PathBuf), AdapterError> {
        if let Some(content) = &self.raw_content {
            return Ok((content.clone(), PathBuf::from("<memory>")));
        }

        let file_path = self.resolve_file()?;
        let content = fs::read_to_string(&file_path).map_err(AdapterError::Io)?;
        Ok((content, file_path))
    }

    /// Convert 2FAS services to common `OtpAccount` structs.
    pub fn parse_services(services: Vec<TwoFasService>) -> Result<Vec<OtpAccount>, AdapterError> {
        let mut accounts = Vec::with_capacity(services.len());

        for (idx, service) in services.into_iter().enumerate() {
            let token_type_str = service
                .otp
                .token_type
                .as_deref()
                .unwrap_or("TOTP")
                .to_uppercase();

            let otp_type = match token_type_str.as_str() {
                "HOTP" => OtpType::Hotp,
                _ => OtpType::Totp, // TOTP and STEAM map to Totp
            };

            let algorithm = match service.otp.algorithm.as_deref() {
                Some(a) => Algorithm::from_str(a).unwrap_or(Algorithm::SHA1),
                None => Algorithm::SHA1,
            };

            // Prefer otp.account -> otp.label -> service.name
            let account_name = service
                .otp
                .account
                .filter(|s| !s.trim().is_empty())
                .or_else(|| service.otp.label.filter(|s| !s.trim().is_empty()))
                .unwrap_or_else(|| service.name.clone());

            // Issuer: prefer otp.issuer, fallback to service.name if different from account name
            let issuer = service
                .otp
                .issuer
                .filter(|s| !s.trim().is_empty())
                .or_else(|| {
                    if service.name != account_name && !service.name.trim().is_empty() {
                        Some(service.name.clone())
                    } else {
                        None
                    }
                });

            let digits = service.otp.digits.unwrap_or_else(|| {
                if token_type_str == "STEAM" {
                    5
                } else {
                    6
                }
            });

            let period = service.otp.period.unwrap_or(30);

            let mut secret = service.secret.trim().to_string();
            // If secret is empty but link is provided, attempt to extract secret from link
            if secret.is_empty() {
                if let Some(link) = &service.otp.link {
                    if let Ok(url) = url::Url::parse(link) {
                        for (k, v) in url.query_pairs() {
                            if k.eq_ignore_ascii_case("secret") {
                                secret = v.into_owned();
                                break;
                            }
                        }
                    }
                }
            }

            let id = format!(
                "2fas:{}:{}:{}",
                service.name,
                account_name,
                service
                    .order
                    .as_ref()
                    .and_then(|o| o.position)
                    .unwrap_or(idx as i64)
            );

            accounts.push(OtpAccount {
                id,
                name: account_name,
                issuer,
                secret,
                algorithm,
                digits,
                period,
                otp_type,
                counter: service.otp.counter,
                icon: None,
                note: None,
            });
        }

        Ok(accounts)
    }
}

impl Source for TwoFasSource {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn load(&self) -> Result<Vec<OtpAccount>, AdapterError> {
        let (raw_json, _) = self.get_content()?;
        let payload: TwoFasPayload = serde_json::from_str(&raw_json)
            .map_err(|e| AdapterError::Format(format!("Invalid 2FAS JSON: {e}")))?;

        match payload {
            TwoFasPayload::List(services) => Self::parse_services(services),
            TwoFasPayload::Object(backup) => {
                if let Some(encrypted_services) = backup.services_encrypted {
                    if !encrypted_services.trim().is_empty() {
                        let password = self
                            .password
                            .as_deref()
                            .ok_or(AdapterError::PasswordRequired)?;

                        let decrypted_json = decrypt_2fas_payload(&encrypted_services, password)?;
                        let decrypted_payload: TwoFasPayload = serde_json::from_str(&decrypted_json)
                            .map_err(|e| {
                                AdapterError::Format(format!(
                                    "Decrypted 2FAS services parsing error: {e}"
                                ))
                            })?;

                        let services = match decrypted_payload {
                            TwoFasPayload::List(list) => list,
                            TwoFasPayload::Object(obj) => obj.services,
                        };

                        return Self::parse_services(services);
                    }
                }

                // If not encrypted, return services array
                Self::parse_services(backup.services)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_plain_2fas() {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/2fas_plain.2fas"
        );
        let source = TwoFasSource::from_file(fixture_path);

        assert!(!source.is_encrypted().unwrap());
        let accounts = source.load().unwrap();
        assert_eq!(accounts.len(), 5);

        let deno = accounts.iter().find(|a| a.name == "Mason").unwrap();
        assert_eq!(deno.issuer, Some("Deno".to_string()));
        assert_eq!(deno.digits, 6);
        assert_eq!(deno.period, 30);
        assert_eq!(deno.algorithm, Algorithm::SHA1);
        assert_eq!(deno.otp_type, OtpType::Totp);
        assert_eq!(deno.secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ");

        let hotp_acc = accounts.iter().find(|a| a.name == "Benjamin").unwrap();
        assert_eq!(hotp_acc.issuer, Some("Air Canada".to_string()));
        assert_eq!(hotp_acc.otp_type, OtpType::Hotp);
        assert_eq!(hotp_acc.digits, 8);
        assert_eq!(hotp_acc.counter, Some(10));
        assert_eq!(hotp_acc.algorithm, Algorithm::SHA256);

        let steam_acc = accounts.iter().find(|a| a.name == "Sophia").unwrap();
        assert_eq!(steam_acc.issuer, Some("Boeing".to_string()));
        assert_eq!(steam_acc.digits, 5);
        assert_eq!(steam_acc.period, 10);
    }

    #[test]
    fn test_load_encrypted_2fas() {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/2fas_encrypted.2fas"
        );
        let source = TwoFasSource::from_file(fixture_path).with_password("example.com");

        assert!(source.is_encrypted().unwrap());
        let accounts = source.load().unwrap();
        assert_eq!(accounts.len(), 5);

        let mason = accounts.iter().find(|a| a.name == "Mason").unwrap();
        assert_eq!(mason.issuer, Some("Deno".to_string()));
        assert_eq!(mason.secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ");
    }

    #[test]
    fn test_wrong_password_fails() {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/2fas_encrypted.2fas"
        );
        let source = TwoFasSource::from_file(fixture_path).with_password("wrong_password");

        let err = source.load().unwrap_err();
        match err {
            AdapterError::InvalidPassword => {}
            other => panic!("Expected InvalidPassword, got: {:?}", other),
        }
    }

    #[test]
    fn test_missing_password_fails() {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/2fas_encrypted.2fas"
        );
        let source = TwoFasSource::from_file(fixture_path);

        let err = source.load().unwrap_err();
        match err {
            AdapterError::PasswordRequired => {}
            other => panic!("Expected PasswordRequired, got: {:?}", other),
        }
    }

    #[test]
    fn test_directory_auto_detects_latest_backup() {
        let temp_dir =
            std::env::temp_dir().join(format!("rune_test_2fas_dir_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let plain_fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/2fas_plain.2fas"
        );
        let enc_fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/2fas_encrypted.2fas"
        );

        let backup1 = temp_dir.join("2fas-backup-20260901_100000.2fas");
        let backup2 = temp_dir.join("2fas-backup-20260902_100000.2fas");
        let backup3 = temp_dir.join("2fas-backup-20260903_120000.2fas");

        let _ = fs::copy(plain_fixture, &backup1);
        let _ = fs::copy(plain_fixture, &backup2);
        let _ = fs::copy(enc_fixture, &backup3); // Latest is encrypted fixture

        let source = TwoFasSource::from_dir(&temp_dir).with_password("example.com");

        let resolved = source.resolve_file().unwrap();
        assert_eq!(resolved, backup3);

        assert!(source.is_encrypted().unwrap());
        let accounts = source.load().unwrap();
        assert_eq!(accounts.len(), 5);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
