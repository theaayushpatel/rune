pub mod crypto;
pub mod schema;

use crypto::{decrypt_database, derive_and_decrypt_master_key};
use rune_core::models::{Algorithm, OtpAccount, OtpType};
use rune_core::source::{AdapterError, Source};
use schema::{AegisDatabase, AegisDbPayload, AegisVault};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Find the latest Aegis backup file in a directory.
/// Scans for `.json` and `.enc` files and picks the newest backup based on modification time and filename.
pub fn find_latest_aegis_backup(dir: &Path) -> Result<PathBuf, AdapterError> {
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
                .map(|e| e.eq_ignore_ascii_case("json") || e.eq_ignore_ascii_case("enc"))
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
            "No Aegis backup files (.json) found in directory: {}",
            dir.display()
        )));
    }

    // Sort: newest mtime first, then lexicographically descending filename
    // e.g. aegis-backup-20260903_120000.json > aegis-backup-20260902_120000.json
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

    Ok(candidates[0].2.clone())
}

/// Source adapter for reading Aegis Authenticator JSON export files or backup directories.
#[derive(Debug, Clone)]
pub struct AegisSource {
    id: String,
    name: String,
    path: Option<PathBuf>,
    raw_content: Option<String>,
    password: Option<String>,
}

impl AegisSource {
    /// Create a source from a file or folder path.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Self {
        let p = path.as_ref().to_path_buf();
        let name = p
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("Aegis Vault")
            .to_string();
        Self {
            id: format!("aegis:{}", p.display()),
            name,
            path: Some(p),
            raw_content: None,
            password: None,
        }
    }

    /// Create a source pointing to an Aegis backup folder (auto-detects the latest backup file).
    pub fn from_dir<P: AsRef<Path>>(dir: P) -> Self {
        Self::from_file(dir)
    }

    /// Create a source directly from JSON content in memory.
    pub fn from_json_str(content: impl Into<String>) -> Self {
        Self {
            id: "aegis:memory".to_string(),
            name: "Aegis Vault (Memory)".to_string(),
            path: None,
            raw_content: Some(content.into()),
            password: None,
        }
    }

    /// Set the decryption password for an encrypted vault.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// If this source points to a directory, dynamically resolve the newest backup file.
    /// Otherwise returns the configured file path.
    pub fn resolve_file(&self) -> Result<PathBuf, AdapterError> {
        if let Some(path) = &self.path {
            if path.is_dir() {
                find_latest_aegis_backup(path)
            } else if path.exists() {
                Ok(path.clone())
            } else {
                Err(AdapterError::NotFound(path.display().to_string()))
            }
        } else {
            Err(AdapterError::Format("No content or path provided".to_string()))
        }
    }

    /// Check whether this Aegis vault (or the latest backup in the folder) is encrypted.
    pub fn is_encrypted(&self) -> Result<bool, AdapterError> {
        let (raw_json, _) = self.get_content()?;
        let vault: AegisVault = serde_json::from_str(&raw_json)
            .map_err(|e| AdapterError::Format(format!("Invalid Aegis JSON: {e}")))?;

        match vault.db {
            AegisDbPayload::Encrypted(_) => Ok(true),
            AegisDbPayload::Plain(_) => Ok(false),
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

    fn parse_database(&self, db: AegisDatabase) -> Result<Vec<OtpAccount>, AdapterError> {
        let mut accounts = Vec::new();

        for entry in db.entries {
            let otp_type = match entry.entry_type.to_lowercase().as_str() {
                "totp" | "steam" => OtpType::Totp,
                "hotp" => OtpType::Hotp,
                _ => OtpType::Totp,
            };

            let algorithm = match &entry.info.algo {
                Some(a) => Algorithm::from_str(a).unwrap_or(Algorithm::SHA1),
                None => Algorithm::SHA1,
            };

            let account = OtpAccount {
                id: entry.uuid,
                name: entry.name,
                issuer: entry.issuer.filter(|s| !s.is_empty()),
                secret: entry.info.secret,
                algorithm,
                digits: entry.info.digits.unwrap_or(6),
                period: entry.info.period.unwrap_or(30),
                otp_type,
                counter: entry.info.counter,
                icon: None,
                note: entry.note.filter(|s| !s.is_empty()),
            };

            accounts.push(account);
        }

        Ok(accounts)
    }
}

impl Source for AegisSource {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn load(&self) -> Result<Vec<OtpAccount>, AdapterError> {
        let (raw_json, _) = self.get_content()?;
        let vault: AegisVault = serde_json::from_str(&raw_json)
            .map_err(|e| AdapterError::Format(format!("Invalid Aegis JSON: {e}")))?;

        match vault.db {
            AegisDbPayload::Plain(db) => self.parse_database(db),
            AegisDbPayload::Encrypted(db_base64) => {
                let password = self
                    .password
                    .as_deref()
                    .ok_or(AdapterError::PasswordRequired)?;

                let slots = vault.header.slots.as_deref().unwrap_or(&[]);
                let master_key = derive_and_decrypt_master_key(slots, password)?;
                let decrypted_json = decrypt_database(&vault.header, &db_base64, master_key)?;

                let db: AegisDatabase = serde_json::from_str(&decrypted_json).map_err(|e| {
                    AdapterError::Format(format!("Decrypted database parsing error: {e}"))
                })?;

                self.parse_database(db)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_plain_aegis() {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/aegis_plain.json"
        );
        let source = AegisSource::from_file(fixture_path);

        assert_eq!(source.is_encrypted().unwrap(), false);
        let accounts = source.load().unwrap();
        assert_eq!(accounts.len(), 7);

        let mason = accounts.iter().find(|a| a.name == "Mason").unwrap();
        assert_eq!(mason.issuer, Some("Deno".to_string()));
        assert_eq!(mason.digits, 6);
        assert_eq!(mason.period, 30);
    }

    #[test]
    fn test_load_encrypted_aegis() {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/aegis_encrypted.json"
        );
        let source = AegisSource::from_file(fixture_path).with_password("test");

        assert_eq!(source.is_encrypted().unwrap(), true);
        let accounts = source.load().unwrap();
        assert_eq!(accounts.len(), 7);

        let mason = accounts.iter().find(|a| a.name == "Mason").unwrap();
        assert_eq!(mason.issuer, Some("Deno".to_string()));
        assert_eq!(mason.secret, "4SJHB4GSD43FZBAI7C2HLRJGPQ");
    }

    #[test]
    fn test_wrong_password_fails() {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/aegis_encrypted.json"
        );
        let source = AegisSource::from_file(fixture_path).with_password("wrong_password");

        let err = source.load().unwrap_err();
        match err {
            AdapterError::InvalidPassword => {}
            other => panic!("Expected InvalidPassword, got: {:?}", other),
        }
    }

    #[test]
    fn test_directory_auto_detects_latest_backup() {
        let temp_dir = std::env::temp_dir().join(format!("rune_test_aegis_dir_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let plain_fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/aegis_plain.json"
        );
        let enc_fixture = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/aegis_encrypted.json"
        );

        // Create 3 simulated synced backups with standard Aegis naming
        let backup1 = temp_dir.join("aegis-backup-20260901_100000.json");
        let backup2 = temp_dir.join("aegis-backup-20260902_100000.json");
        let backup3 = temp_dir.join("aegis-backup-20260903_120000.json");

        let _ = fs::copy(plain_fixture, &backup1);
        let _ = fs::copy(plain_fixture, &backup2);
        let _ = fs::copy(enc_fixture, &backup3); // Latest is encrypted fixture

        // Point AegisSource to the directory
        let source = AegisSource::from_dir(&temp_dir).with_password("test");

        let resolved = source.resolve_file().unwrap();
        assert_eq!(resolved, backup3);

        assert_eq!(source.is_encrypted().unwrap(), true);
        let accounts = source.load().unwrap();
        assert_eq!(accounts.len(), 7);

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
