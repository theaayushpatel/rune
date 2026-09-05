use keepass::db::{fields, Database, EntryRef, GroupRef};
use keepass::error::{DatabaseKeyError, DatabaseOpenError};
use keepass::DatabaseKey;
use rune_adapter_uri::UriSource;
use rune_core::models::{Algorithm, OtpAccount, OtpType};
use rune_core::otp::decode_secret;
use rune_core::source::{AdapterError, Source};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::str::FromStr;

/// Find the latest KeePassXC database file (.kdbx) in a directory.
/// Scans for `.kdbx` files and returns the newest file based on modification time and filename.
pub fn find_latest_kdbx_file(dir: &Path) -> Result<PathBuf, AdapterError> {
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
            let is_kdbx = path
                .extension()
                .and_then(|e| e.to_str())
                .map(|e| e.eq_ignore_ascii_case("kdbx"))
                .unwrap_or(false);

            if is_kdbx {
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
            "No KeePass database files (.kdbx) found in directory: {}",
            dir.display()
        )));
    }

    // Sort: newest mtime first, then lexicographically descending filename
    candidates.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| b.1.cmp(&a.1)));

    Ok(candidates[0].2.clone())
}

/// Source adapter for reading KeePass / KeePassXC database files (.kdbx) or backup directories.
#[derive(Debug, Clone)]
pub struct KdbxSource {
    id: String,
    name: String,
    path: Option<PathBuf>,
    raw_bytes: Option<Vec<u8>>,
    password: Option<String>,
    keyfile: Option<PathBuf>,
}

impl KdbxSource {
    /// Create a source from a `.kdbx` file path or directory.
    pub fn from_file<P: AsRef<Path>>(path: P) -> Self {
        let p = path.as_ref().to_path_buf();
        let name = p
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("KeePassXC Database")
            .to_string();
        Self {
            id: format!("kdbx:{}", p.display()),
            name,
            path: Some(p),
            raw_bytes: None,
            password: None,
            keyfile: None,
        }
    }

    /// Create a source pointing to a directory containing `.kdbx` files (auto-detects newest).
    pub fn from_dir<P: AsRef<Path>>(dir: P) -> Self {
        Self::from_file(dir)
    }

    /// Create a source directly from raw database bytes in memory.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> Self {
        Self {
            id: "kdbx:memory".to_string(),
            name: "KeePassXC Database (Memory)".to_string(),
            path: None,
            raw_bytes: Some(bytes.into()),
            password: None,
            keyfile: None,
        }
    }

    /// Set the master password for database decryption.
    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.password = Some(password.into());
        self
    }

    /// Set the keyfile path for database decryption.
    pub fn with_keyfile<P: AsRef<Path>>(mut self, keyfile: P) -> Self {
        self.keyfile = Some(keyfile.as_ref().to_path_buf());
        self
    }

    /// If this source points to a directory, dynamically resolve the newest `.kdbx` file.
    /// Otherwise returns the configured file path.
    pub fn resolve_file(&self) -> Result<PathBuf, AdapterError> {
        if let Some(path) = &self.path {
            if path.is_dir() {
                find_latest_kdbx_file(path)
            } else if path.exists() {
                Ok(path.clone())
            } else {
                Err(AdapterError::NotFound(path.display().to_string()))
            }
        } else {
            Err(AdapterError::Format("No content or path provided".to_string()))
        }
    }

    /// Check whether this source is encrypted (KDBX databases are always encrypted master vaults).
    pub fn is_encrypted(&self) -> Result<bool, AdapterError> {
        Ok(true)
    }
}

/// Helper to parse query parameters (e.g. `key=...&step=30&size=6&algorithm=SHA1`)
fn parse_otp_query(query_str: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let query_part = if let Some((_host, q)) = query_str.split_once('?') {
        q
    } else {
        query_str
    };

    for pair in query_part.split('&') {
        let trimmed = pair.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            map.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    map
}

/// Parse TrayTOTP algorithm format, e.g. "HMAC-SHA-1", "HMAC-SHA-256", "SHA512"
fn parse_traytotp_algo(s: &str) -> Algorithm {
    let trimmed = s.trim().to_ascii_uppercase();
    let normalized = trimmed.trim_start_matches("HMAC-");
    Algorithm::from_str(normalized).unwrap_or(Algorithm::SHA1)
}

/// Parse KeeOtp format settings string (e.g. "30;6", "30;8;256", "30;6;1", "60;6;sha512", "30")
fn parse_totp_settings(settings: &str) -> (Option<u32>, Option<u32>, Option<Algorithm>) {
    let parts: Vec<&str> = settings
        .split([';', ':', ',', '/'])
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    let period = parts.first().and_then(|p| p.parse::<u32>().ok());
    let digits = parts.get(1).and_then(|d| d.parse::<u32>().ok());
    let algorithm = parts.get(2).and_then(|algo| {
        match *algo {
            "1" | "SHA1" | "sha1" | "HMAC-SHA-1" => Some(Algorithm::SHA1),
            "2" | "256" | "SHA256" | "sha256" | "HMAC-SHA-256" => Some(Algorithm::SHA256),
            "3" | "512" | "SHA512" | "sha512" | "HMAC-SHA-512" => Some(Algorithm::SHA512),
            other => {
                let norm = other.to_ascii_uppercase();
                let norm = norm.trim_start_matches("HMAC-");
                Algorithm::from_str(norm).ok()
            }
        }
    });
    (period, digits, algorithm)
}

/// Extract an embedded `otpauth://` URI from a text block (e.g. Notes field).
/// Returns `(uri_string, remaining_notes_text)` if an `otpauth://` URI is found.
fn extract_otpauth_from_text(text: &str) -> Option<(String, Option<String>)> {
    let mut found_uri = None;
    let mut remaining_lines = Vec::new();

    for line in text.lines() {
        let trimmed = line.trim();
        if found_uri.is_none() {
            if let Some(idx) = trimmed.find("otpauth://") {
                let uri_slice = &trimmed[idx..];
                let uri_str = uri_slice.split_whitespace().next().unwrap_or(uri_slice);
                found_uri = Some(uri_str.to_string());
                let before = trimmed[..idx].trim();
                if !before.is_empty() {
                    remaining_lines.push(before);
                }
                continue;
            }
        }
        if !trimmed.is_empty() {
            remaining_lines.push(trimmed);
        }
    }

    let remaining_note = if remaining_lines.is_empty() {
        None
    } else {
        Some(remaining_lines.join("\n"))
    };

    found_uri.map(|uri| (uri, remaining_note))
}

/// Clean and normalize a raw secret string (handles spaces, dashes, Base32 normalization, or hex decode).
fn normalize_secret(raw: &str) -> Option<String> {
    let clean = raw.trim().replace([' ', '-'], "").to_ascii_uppercase();
    if clean.is_empty() {
        return None;
    }
    // Try Base32 first
    if decode_secret(&clean).is_ok() {
        return Some(clean);
    }
    // Try hex decoding fallback
    if let Ok(bytes) = hex::decode(&clean) {
        if !bytes.is_empty() {
            return Some(data_encoding::BASE32_NOPAD.encode(&bytes));
        }
    }
    None
}

/// Parse an individual KeePassXC entry into an `OtpAccount` if it contains TOTP configuration.
pub fn parse_kdbx_entry(entry: &EntryRef<'_>, group_path: &str) -> Option<OtpAccount> {
    let raw_title = entry.get_title().unwrap_or("").trim();
    let raw_username = entry.get_username().unwrap_or("").trim();
    let raw_notes = entry
        .get(fields::NOTES)
        .or_else(|| entry.get("Notes"))
        .or_else(|| entry.get("notes"))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let entry_uuid_str = entry.id().to_string();
    let default_id = format!("kdbx:{entry_uuid_str}");

    let make_combined_note = |note_opt: Option<String>| match (note_opt, group_path.is_empty()) {
        (Some(n), false) => Some(format!("{n} [{group_path}]")),
        (Some(n), true) => Some(n),
        (None, false) => Some(format!("[{group_path}]")),
        (None, true) => None,
    };

    // Helper to enrich account name/issuer if generic
    let enrich_account = |mut acc: OtpAccount, note: Option<String>| -> OtpAccount {
        let is_generic_name = acc.name.is_empty()
            || acc.name.eq_ignore_ascii_case("none")
            || acc.name.eq_ignore_ascii_case("KeePassXC")
            || acc.name.eq_ignore_ascii_case("KeePass")
            || acc.name == "Unnamed Account";

        if is_generic_name {
            if !raw_username.is_empty() {
                acc.name = raw_username.to_string();
            } else if !raw_title.is_empty() {
                acc.name = raw_title.to_string();
            }
        }

        let is_generic_issuer = acc
            .issuer
            .as_deref()
            .map(|i| {
                i.eq_ignore_ascii_case("KeePassXC")
                    || i.eq_ignore_ascii_case("KeePass")
                    || i.trim().is_empty()
            })
            .unwrap_or(true);

        if is_generic_issuer && !raw_title.is_empty() && raw_title != acc.name {
            acc.issuer = Some(raw_title.to_string());
        }

        if acc.note.is_none() {
            acc.note = note;
        }

        acc
    };

    // 1. Check primary OTP fields: 'otp', 'OTP', 'totp', 'TOTP', 'otpauth', 'otpauth_url', 'kp2a_totp', '2FA', '2fa'
    let primary_otp = entry
        .get_raw_otp_value()
        .or_else(|| entry.get("otp"))
        .or_else(|| entry.get("OTP"))
        .or_else(|| entry.get("totp"))
        .or_else(|| entry.get("TOTP"))
        .or_else(|| entry.get("otpauth"))
        .or_else(|| entry.get("otpauth_url"))
        .or_else(|| entry.get("kp2a_totp"))
        .or_else(|| entry.get("2FA"))
        .or_else(|| entry.get("2fa"));

    if let Some(raw_otp) = primary_otp {
        let trimmed = raw_otp.trim();
        if !trimmed.is_empty() {
            // Case 1A: otpauth:// URI
            if trimmed.starts_with("otpauth://") {
                if let Ok(mut account) = UriSource::parse_uri(trimmed) {
                    account.id = default_id;
                    return Some(enrich_account(account, make_combined_note(raw_notes)));
                }
            }

            // Case 1B: RFC 6238 key-value parameters (e.g. key=...&step=30&size=6&algorithm=SHA1)
            if trimmed.contains("key=") || trimmed.contains("secret=") {
                let params = parse_otp_query(trimmed);
                if let Some(secret) = params.get("key").or_else(|| params.get("secret")) {
                    if let Some(clean_secret) = normalize_secret(secret) {
                        let period = params
                            .get("step")
                            .or_else(|| params.get("period"))
                            .and_then(|v| v.parse::<u32>().ok())
                            .unwrap_or(30);

                        let digits = params
                            .get("size")
                            .or_else(|| params.get("digits"))
                            .and_then(|v| v.parse::<u32>().ok())
                            .unwrap_or(6);

                        let algorithm = params
                            .get("algorithm")
                            .and_then(|v| Algorithm::from_str(v).ok())
                            .unwrap_or(Algorithm::SHA1);

                        let counter = params.get("counter").and_then(|v| v.parse::<u64>().ok());
                        let otp_type = if counter.is_some() {
                            OtpType::Hotp
                        } else {
                            OtpType::Totp
                        };

                        let (name, issuer) = if !raw_username.is_empty() {
                            (
                                raw_username.to_string(),
                                if !raw_title.is_empty() && raw_title != raw_username {
                                    Some(raw_title.to_string())
                                } else {
                                    None
                                },
                            )
                        } else {
                            (
                                if !raw_title.is_empty() {
                                    raw_title.to_string()
                                } else {
                                    "KeePassXC Account".to_string()
                                },
                                None,
                            )
                        };

                        return Some(OtpAccount {
                            id: default_id,
                            name,
                            issuer,
                            secret: clean_secret,
                            algorithm,
                            digits,
                            period,
                            otp_type,
                            counter,
                            icon: None,
                            note: make_combined_note(raw_notes),
                        });
                    }
                }
            }

            // Case 1C: Raw Base32 string in 'otp' field
            if let Some(clean_secret) = normalize_secret(trimmed) {
                if clean_secret.len() >= 8 {
                    let (name, issuer) = if !raw_username.is_empty() {
                        (
                            raw_username.to_string(),
                            if !raw_title.is_empty() && raw_title != raw_username {
                                Some(raw_title.to_string())
                            } else {
                                None
                            },
                        )
                    } else {
                        (
                            if !raw_title.is_empty() {
                                raw_title.to_string()
                            } else {
                                "KeePassXC Account".to_string()
                            },
                            None,
                        )
                    };

                    return Some(OtpAccount {
                        id: default_id,
                        name,
                        issuer,
                        secret: clean_secret,
                        algorithm: Algorithm::SHA1,
                        digits: 6,
                        period: 30,
                        otp_type: OtpType::Totp,
                        counter: None,
                        icon: None,
                        note: make_combined_note(raw_notes),
                    });
                }
            }
        }
    }

    // 2. Check TrayTOTP / KeeOTP formats
    let tray_secret_raw = entry
        .get("TimeOtp-Secret-Base32")
        .or_else(|| entry.get("HmacOTP-Secret-Base32"))
        .or_else(|| entry.get("TOTP Seed"))
        .or_else(|| entry.get("totpSeed"))
        .or_else(|| entry.get("totp_seed"))
        .or_else(|| entry.get("TOTP_SEED"))
        .or_else(|| entry.get("TimeOtp-Secret-Hex"));

    if let Some(raw_sec) = tray_secret_raw {
        if let Some(clean_secret) = normalize_secret(raw_sec) {
            // Check KeeOtp 'TOTP Settings'
            let totp_settings = entry
                .get("TOTP Settings")
                .or_else(|| entry.get("totpSettings"))
                .or_else(|| entry.get("totp_settings"))
                .or_else(|| entry.get("TOTP_SETTINGS"))
                .map(parse_totp_settings)
                .unwrap_or((None, None, None));

            let period = entry
                .get("TimeOtp-Period")
                .and_then(|v| v.trim().parse::<u32>().ok())
                .or(totp_settings.0)
                .unwrap_or(30);

            let digits = entry
                .get("TimeOtp-Length")
                .and_then(|v| v.trim().parse::<u32>().ok())
                .or(totp_settings.1)
                .unwrap_or(6);

            let algorithm = entry
                .get("TimeOtp-Algorithm")
                .map(parse_traytotp_algo)
                .or(totp_settings.2)
                .unwrap_or(Algorithm::SHA1);

            let counter = entry
                .get("HmacOTP-Counter")
                .and_then(|v| v.trim().parse::<u64>().ok());

            let otp_type = if counter.is_some() {
                OtpType::Hotp
            } else {
                OtpType::Totp
            };

            let (name, issuer) = if !raw_username.is_empty() {
                (
                    raw_username.to_string(),
                    if !raw_title.is_empty() && raw_title != raw_username {
                        Some(raw_title.to_string())
                    } else {
                        None
                    },
                )
            } else {
                (
                    if !raw_title.is_empty() {
                        raw_title.to_string()
                    } else {
                        "KeePass Account".to_string()
                    },
                    None,
                )
            };

            return Some(OtpAccount {
                id: default_id,
                name,
                issuer,
                secret: clean_secret,
                algorithm,
                digits,
                period,
                otp_type,
                counter,
                icon: None,
                note: make_combined_note(raw_notes),
            });
        }
    }

    // 3. Check 'URL' field for otpauth://
    let url_val = entry
        .get(fields::URL)
        .or_else(|| entry.get("URL"))
        .or_else(|| entry.get("url"))
        .or_else(|| entry.get("Url"));

    if let Some(raw_url) = url_val {
        let trimmed = raw_url.trim();
        if trimmed.starts_with("otpauth://") {
            if let Ok(mut account) = UriSource::parse_uri(trimmed) {
                account.id = default_id;
                return Some(enrich_account(account, make_combined_note(raw_notes)));
            }
        }
    }

    // 4. Check 'Notes' field for embedded otpauth:// URI
    if let Some(notes_text) = &raw_notes {
        if let Some((uri_str, remaining_note)) = extract_otpauth_from_text(notes_text) {
            if let Ok(mut account) = UriSource::parse_uri(&uri_str) {
                account.id = default_id;
                return Some(enrich_account(account, make_combined_note(remaining_note)));
            }
        }
    }

    None
}

/// Recursively collect OTP accounts from groups, excluding the Recycle Bin.
fn collect_group(
    group: GroupRef<'_>,
    group_path: &str,
    recyclebin_uuid: Option<uuid::Uuid>,
    out: &mut Vec<OtpAccount>,
) {
    let group_name = group.name.trim();

    // Check if group is the recycle bin
    let is_recycle_bin = recyclebin_uuid
        .map(|u| u == group.id().uuid())
        .unwrap_or(false)
        || group_name.eq_ignore_ascii_case("Recycle Bin")
        || group_name.eq_ignore_ascii_case("Trash");

    if is_recycle_bin {
        return;
    }

    let current_path = if group_path.is_empty() {
        group_name.to_string()
    } else {
        format!("{group_path}/{group_name}")
    };

    for entry in group.entries() {
        if let Some(account) = parse_kdbx_entry(&entry, &current_path) {
            out.push(account);
        }
    }

    for sub_group in group.groups() {
        collect_group(sub_group, &current_path, recyclebin_uuid, out);
    }
}

impl Source for KdbxSource {
    fn id(&self) -> &str {
        &self.id
    }

    fn name(&self) -> &str {
        &self.name
    }

    fn load(&self) -> Result<Vec<OtpAccount>, AdapterError> {
        let mut key = DatabaseKey::new();

        if let Some(pwd) = &self.password {
            key = key.with_password(pwd);
        }

        if let Some(kf_path) = &self.keyfile {
            if !kf_path.exists() {
                return Err(AdapterError::NotFound(format!(
                    "Keyfile not found: {}",
                    kf_path.display()
                )));
            }
            let mut kf_file = File::open(kf_path).map_err(AdapterError::Io)?;
            key = key.with_keyfile(&mut kf_file).map_err(|e| {
                AdapterError::Format(format!(
                    "Failed to read keyfile '{}': {e}",
                    kf_path.display()
                ))
            })?;
        }

        if key.is_empty() {
            return Err(AdapterError::PasswordRequired);
        }

        let db = if let Some(bytes) = &self.raw_bytes {
            let mut cursor = Cursor::new(bytes.as_slice());
            Database::open(&mut cursor, key)
        } else {
            let file_path = self.resolve_file()?;
            let mut file = File::open(&file_path).map_err(AdapterError::Io)?;
            Database::open(&mut file, key)
        };

        let db = match db {
            Ok(d) => d,
            Err(DatabaseOpenError::Key(DatabaseKeyError::IncorrectKey)) => {
                return Err(AdapterError::InvalidPassword);
            }
            Err(DatabaseOpenError::Key(DatabaseKeyError::EmptyKey)) => {
                return Err(AdapterError::PasswordRequired);
            }
            Err(DatabaseOpenError::Io(e)) => return Err(AdapterError::Io(e)),
            Err(e) => return Err(AdapterError::Decryption(e.to_string())),
        };

        let recyclebin_uuid = db.meta.recyclebin_uuid;
        let mut accounts = Vec::new();

        collect_group(db.root(), "", recyclebin_uuid, &mut accounts);

        Ok(accounts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_db() -> Vec<u8> {
        let mut db = Database::new();

        // 1. otpauth:// URI entry
        let e1 = db.root_mut().add_entry().id();
        db.root_mut().entry_mut(e1).unwrap().edit(|e| {
            e.set_unprotected(fields::TITLE, "GitHub");
            e.set_unprotected(fields::USERNAME, "octocat");
            e.set_unprotected(
                fields::OTP,
                "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA1&digits=6&period=30",
            );
        });

        // 2. key=... query format entry
        let e2 = db.root_mut().add_entry().id();
        db.root_mut().entry_mut(e2).unwrap().edit(|e| {
            e.set_unprotected(fields::TITLE, "Google");
            e.set_unprotected(fields::USERNAME, "alice@gmail.com");
            e.set_unprotected(
                fields::OTP,
                "key=HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ&step=30&size=6&algorithm=SHA1",
            );
        });

        // 3. TrayTOTP format entry
        let e3 = db.root_mut().add_entry().id();
        db.root_mut().entry_mut(e3).unwrap().edit(|e| {
            e.set_unprotected(fields::TITLE, "Cloudflare");
            e.set_unprotected(fields::USERNAME, "ops");
            e.set_unprotected("TimeOtp-Secret-Base32", "GEZDGNBVGY3TQOJQ");
            e.set_unprotected("TimeOtp-Period", "30");
            e.set_unprotected("TimeOtp-Length", "8");
            e.set_unprotected("TimeOtp-Algorithm", "HMAC-SHA-256");
        });

        // 4. Raw Base32 string in 'otp'
        let e4 = db.root_mut().add_entry().id();
        db.root_mut().entry_mut(e4).unwrap().edit(|e| {
            e.set_unprotected(fields::TITLE, "AWS");
            e.set_unprotected(fields::USERNAME, "root");
            e.set_unprotected(fields::OTP, "JBSWY3DPEHPK3PXP");
        });

        // 5. Standard non-TOTP entry (should be ignored)
        let e5 = db.root_mut().add_entry().id();
        db.root_mut().entry_mut(e5).unwrap().edit(|e| {
            e.set_unprotected(fields::TITLE, "Regular Password");
            e.set_unprotected(fields::PASSWORD, "secret123");
        });

        // 6. Subgroup named 'Recycle Bin' with a TOTP entry (must be skipped)
        let rb_id = db.root_mut().add_group().id();
        db.root_mut().group_mut(rb_id).unwrap().edit(|g| {
            g.name = "Recycle Bin".to_string();
        });
        let e_trash = db.root_mut().group_mut(rb_id).unwrap().add_entry().id();
        db.root_mut()
            .group_mut(rb_id)
            .unwrap()
            .entry_mut(e_trash)
            .unwrap()
            .edit(|e| {
                e.set_unprotected(fields::TITLE, "Deleted TOTP");
                e.set_unprotected(fields::OTP, "otpauth://totp/Deleted:user?secret=JBSWY3DPEHPK3PXP");
            });

        let mut buf = Vec::new();
        let key = DatabaseKey::new().with_password("password123");
        db.save(&mut buf, key).expect("Failed to save test db");
        buf
    }

    #[test]
    fn test_load_kdbx_accounts() {
        let db_bytes = create_test_db();
        let source = KdbxSource::from_bytes(db_bytes).with_password("password123");

        assert!(source.is_encrypted().unwrap());
        let accounts = source.load().unwrap();
        // 4 active accounts (non-TOTP and Recycle Bin accounts are excluded)
        assert_eq!(accounts.len(), 4);

        // Verify OTP code generation for all extracted accounts
        for acc in &accounts {
            let code = rune_core::otp::generate_account_code(acc, Some(1700000000)).unwrap();
            assert_eq!(code.len(), acc.digits as usize);
        }

        // Verify GitHub (URI format)
        let github = accounts.iter().find(|a| a.name == "octocat").unwrap();
        assert_eq!(github.issuer, Some("GitHub".to_string()));
        assert_eq!(github.secret, "JBSWY3DPEHPK3PXP");
        assert_eq!(github.digits, 6);
        assert_eq!(github.period, 30);
        assert_eq!(github.algorithm, Algorithm::SHA1);

        // Verify Google (key=... query format)
        let google = accounts.iter().find(|a| a.name == "alice@gmail.com").unwrap();
        assert_eq!(google.issuer, Some("Google".to_string()));
        assert_eq!(google.secret, "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ");
        assert_eq!(google.digits, 6);
        assert_eq!(google.period, 30);

        // Verify Cloudflare (TrayTOTP format, 8 digits, SHA256)
        let cf = accounts.iter().find(|a| a.name == "ops").unwrap();
        assert_eq!(cf.issuer, Some("Cloudflare".to_string()));
        assert_eq!(cf.secret, "GEZDGNBVGY3TQOJQ");
        assert_eq!(cf.digits, 8);
        assert_eq!(cf.period, 30);
        assert_eq!(cf.algorithm, Algorithm::SHA256);

        // Verify AWS (raw Base32 secret)
        let aws = accounts.iter().find(|a| a.name == "root").unwrap();
        assert_eq!(aws.issuer, Some("AWS".to_string()));
        assert_eq!(aws.secret, "JBSWY3DPEHPK3PXP");
    }

    #[test]
    fn test_keeotp_settings_format() {
        let mut db = Database::new();

        // KeeOtp with custom TOTP Settings (30;8;256)
        let e1 = db.root_mut().add_entry().id();
        db.root_mut().entry_mut(e1).unwrap().edit(|e| {
            e.set_unprotected(fields::TITLE, "GitLab");
            e.set_unprotected(fields::USERNAME, "developer");
            e.set_unprotected("TOTP Seed", "HXDMVJECJJWSRB3HWIZR4IFUGFTMXBOZ");
            e.set_unprotected("TOTP Settings", "30;8;256");
        });

        // KeeOtp with custom TOTP Settings (60;6;512)
        let e2 = db.root_mut().add_entry().id();
        db.root_mut().entry_mut(e2).unwrap().edit(|e| {
            e.set_unprotected(fields::TITLE, "DigitalOcean");
            e.set_unprotected(fields::USERNAME, "admin@do.com");
            e.set_unprotected("totpSeed", "GEZDGNBVGY3TQOJQ");
            e.set_unprotected("totpSettings", "60;6;512");
        });

        let mut buf = Vec::new();
        let key = DatabaseKey::new().with_password("testpwd");
        db.save(&mut buf, key).unwrap();

        let source = KdbxSource::from_bytes(buf).with_password("testpwd");
        let accounts = source.load().unwrap();
        assert_eq!(accounts.len(), 2);

        let gitlab = accounts.iter().find(|a| a.name == "developer").unwrap();
        assert_eq!(gitlab.issuer, Some("GitLab".to_string()));
        assert_eq!(gitlab.digits, 8);
        assert_eq!(gitlab.period, 30);
        assert_eq!(gitlab.algorithm, Algorithm::SHA256);

        let do_acc = accounts.iter().find(|a| a.name == "admin@do.com").unwrap();
        assert_eq!(do_acc.issuer, Some("DigitalOcean".to_string()));
        assert_eq!(do_acc.digits, 6);
        assert_eq!(do_acc.period, 60);
        assert_eq!(do_acc.algorithm, Algorithm::SHA512);
    }

    #[test]
    fn test_kp2a_totp_and_url_and_notes_fallbacks() {
        let mut db = Database::new();

        // KeePass2Android custom attribute kp2a_totp
        let e1 = db.root_mut().add_entry().id();
        db.root_mut().entry_mut(e1).unwrap().edit(|e| {
            e.set_unprotected(fields::TITLE, "Bitbucket");
            e.set_unprotected(fields::USERNAME, "bituser");
            e.set_unprotected(
                "kp2a_totp",
                "otpauth://totp/Bitbucket:bituser?secret=JBSWY3DPEHPK3PXP&issuer=Bitbucket",
            );
        });

        // URL field containing otpauth://
        let e2 = db.root_mut().add_entry().id();
        db.root_mut().entry_mut(e2).unwrap().edit(|e| {
            e.set_unprotected(fields::TITLE, "ProtonMail");
            e.set_unprotected(fields::USERNAME, "proton@pm.me");
            e.set_unprotected(
                fields::URL,
                "otpauth://totp/ProtonMail:proton@pm.me?secret=GEZDGNBVGY3TQOJQ",
            );
        });

        // Notes field containing embedded otpauth:// URI amidst other notes
        let e3 = db.root_mut().add_entry().id();
        db.root_mut().entry_mut(e3).unwrap().edit(|e| {
            e.set_unprotected(fields::TITLE, "Vercel");
            e.set_unprotected(fields::USERNAME, "dev");
            e.set_unprotected(
                fields::NOTES,
                "Important recovery info\notpauth://totp/Vercel:dev?secret=JBSWY3DPEHPK3PXP\nKeep safe",
            );
        });

        // Hex encoded TrayTOTP secret
        let e4 = db.root_mut().add_entry().id();
        db.root_mut().entry_mut(e4).unwrap().edit(|e| {
            e.set_unprotected(fields::TITLE, "Fastmail");
            e.set_unprotected(fields::USERNAME, "fast@fm.com");
            // "48656c6c6f21deadbeef" hex
            e.set_unprotected("TimeOtp-Secret-Hex", "48656c6c6f21deadbeef");
            e.set_unprotected("TimeOtp-Period", "30");
            e.set_unprotected("TimeOtp-Length", "6");
        });

        let mut buf = Vec::new();
        let key = DatabaseKey::new().with_password("fallback_pwd");
        db.save(&mut buf, key).unwrap();

        let source = KdbxSource::from_bytes(buf).with_password("fallback_pwd");
        let accounts = source.load().unwrap();
        assert_eq!(accounts.len(), 4);

        let bb = accounts.iter().find(|a| a.name == "bituser").unwrap();
        assert_eq!(bb.issuer, Some("Bitbucket".to_string()));

        let proton = accounts.iter().find(|a| a.name == "proton@pm.me").unwrap();
        assert_eq!(proton.issuer, Some("ProtonMail".to_string()));

        let vercel = accounts.iter().find(|a| a.name == "dev").unwrap();
        assert_eq!(vercel.issuer, Some("Vercel".to_string()));
        assert!(vercel.note.as_deref().unwrap_or("").contains("Important recovery info"));

        let fastmail = accounts.iter().find(|a| a.name == "fast@fm.com").unwrap();
        assert_eq!(fastmail.issuer, Some("Fastmail".to_string()));
        assert!(!fastmail.secret.is_empty());
    }

    #[test]
    fn test_keyfile_and_composite_key_authentication() {
        let temp_dir =
            std::env::temp_dir().join(format!("rune_test_kdbx_kf_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let keyfile_path = temp_dir.join("test.key");
        fs::write(&keyfile_path, b"super_secure_random_keyfile_bytes_32_chars!").unwrap();

        let db_path = temp_dir.join("composite_vault.kdbx");

        // 1. Create DB with composite key (password + keyfile)
        {
            let mut db = Database::new();
            let e1 = db.root_mut().add_entry().id();
            db.root_mut().entry_mut(e1).unwrap().edit(|e| {
                e.set_unprotected(fields::TITLE, "CompositeAuth");
                e.set_unprotected(fields::USERNAME, "admin");
                e.set_unprotected(fields::OTP, "JBSWY3DPEHPK3PXP");
            });

            let mut kf_file = File::open(&keyfile_path).unwrap();
            let key = DatabaseKey::new()
                .with_password("master_password_123")
                .with_keyfile(&mut kf_file)
                .unwrap();

            let mut db_file = File::create(&db_path).unwrap();
            db.save(&mut db_file, key).unwrap();
        }

        // Test loading with correct password AND keyfile
        {
            let source = KdbxSource::from_file(&db_path)
                .with_password("master_password_123")
                .with_keyfile(&keyfile_path);
            let accounts = source.load().unwrap();
            assert_eq!(accounts.len(), 1);
            assert_eq!(accounts[0].name, "admin");
        }

        // Test loading with password only (should fail)
        {
            let source = KdbxSource::from_file(&db_path).with_password("master_password_123");
            let err = source.load().unwrap_err();
            match err {
                AdapterError::InvalidPassword | AdapterError::Decryption(_) => {}
                other => panic!("Expected InvalidPassword or Decryption, got: {:?}", other),
            }
        }

        // Test loading with keyfile only (should fail)
        {
            let source = KdbxSource::from_file(&db_path).with_keyfile(&keyfile_path);
            let err = source.load().unwrap_err();
            match err {
                AdapterError::InvalidPassword | AdapterError::Decryption(_) => {}
                other => panic!("Expected InvalidPassword or Decryption, got: {:?}", other),
            }
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_wrong_password_fails() {
        let db_bytes = create_test_db();
        let source = KdbxSource::from_bytes(db_bytes).with_password("wrong_password");

        let err = source.load().unwrap_err();
        match err {
            AdapterError::InvalidPassword => {}
            other => panic!("Expected InvalidPassword, got: {:?}", other),
        }
    }

    #[test]
    fn test_missing_password_fails() {
        let db_bytes = create_test_db();
        let source = KdbxSource::from_bytes(db_bytes);

        let err = source.load().unwrap_err();
        match err {
            AdapterError::PasswordRequired => {}
            other => panic!("Expected PasswordRequired, got: {:?}", other),
        }
    }

    #[test]
    fn test_directory_auto_detects_latest_kdbx() {
        let temp_dir =
            std::env::temp_dir().join(format!("rune_test_kdbx_dir_{}", std::process::id()));
        let _ = fs::create_dir_all(&temp_dir);

        let db_bytes = create_test_db();
        let backup1 = temp_dir.join("passwords-2026-09-01.kdbx");
        let backup2 = temp_dir.join("passwords-2026-09-02.kdbx");

        let _ = fs::write(&backup1, &db_bytes);
        // Ensure mtime difference
        std::thread::sleep(std::time::Duration::from_millis(50));
        let _ = fs::write(&backup2, &db_bytes);

        let source = KdbxSource::from_dir(&temp_dir).with_password("password123");
        let resolved = source.resolve_file().unwrap();
        assert_eq!(resolved, backup2);

        let accounts = source.load().unwrap();
        assert_eq!(accounts.len(), 4);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_load_example_kdbx_file() {
        let fixture_path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../examples/keepass_vault.kdbx"
        );
        let source = KdbxSource::from_file(fixture_path).with_password("password123");

        assert!(source.is_encrypted().unwrap());
        let accounts = source.load().unwrap();
        assert_eq!(accounts.len(), 4);

        let names: Vec<&str> = accounts.iter().map(|a| a.name.as_str()).collect();
        assert!(names.contains(&"octocat"));
        assert!(names.contains(&"alice@gmail.com"));
        assert!(names.contains(&"admin"));
        assert!(names.contains(&"root"));
    }
}
