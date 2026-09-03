use crate::schema::{AegisHeader, AegisSlot};
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rune_core::source::AdapterError;
use zeroize::Zeroize;

/// Decrypt the master key from one of the vault's password slots using the provided password.
pub fn derive_and_decrypt_master_key(
    slots: &[AegisSlot],
    password: &str,
) -> Result<Vec<u8>, AdapterError> {
    // Password slots have type 1
    let password_slots: Vec<&AegisSlot> = slots.iter().filter(|s| s.slot_type == 1).collect();
    if password_slots.is_empty() {
        return Err(AdapterError::Decryption(
            "No password slot found in Aegis header".to_string(),
        ));
    }

    for slot in password_slots {
        let salt = hex::decode(&slot.salt)
            .map_err(|e| AdapterError::Format(format!("Invalid hex salt in slot: {e}")))?;

        // In scrypt, n must be a power of 2. Compute log2(n).
        if slot.n == 0 || (slot.n & (slot.n - 1)) != 0 {
            continue;
        }
        let log_n = slot.n.trailing_zeros() as u8;

        let params = scrypt::Params::new(log_n, slot.r, slot.p, 32)
            .map_err(|e| AdapterError::Decryption(format!("Invalid scrypt parameters: {e}")))?;

        let mut derived_key = [0u8; 32];
        if scrypt::scrypt(password.as_bytes(), &salt, &params, &mut derived_key).is_err() {
            continue;
        }

        // Attempt decrypting the master key using the derived key
        let cipher = Aes256Gcm::new_from_slice(&derived_key)
            .map_err(|e| AdapterError::Decryption(e.to_string()))?;

        let nonce_bytes = match hex::decode(&slot.key_params.nonce) {
            Ok(n) => n,
            Err(_) => continue,
        };
        let tag_bytes = match hex::decode(&slot.key_params.tag) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let mut key_cipher = match hex::decode(&slot.key) {
            Ok(k) => k,
            Err(_) => continue,
        };
        key_cipher.extend_from_slice(&tag_bytes);

        let nonce = Nonce::from_slice(&nonce_bytes);
        let decrypt_result = cipher.decrypt(nonce, key_cipher.as_ref());
        derived_key.zeroize();

        if let Ok(master_key) = decrypt_result {
            return Ok(master_key);
        }
    }

    Err(AdapterError::InvalidPassword)
}

/// Decrypt the base64-encoded Aegis database using the master key.
pub fn decrypt_database(
    header: &AegisHeader,
    db_base64: &str,
    mut master_key: Vec<u8>,
) -> Result<String, AdapterError> {
    let params = header.params.as_ref().ok_or_else(|| {
        AdapterError::Decryption("Missing encryption params in header".to_string())
    })?;

    let nonce_bytes = hex::decode(&params.nonce)
        .map_err(|e| AdapterError::Format(format!("Invalid nonce hex: {e}")))?;
    let tag_bytes = hex::decode(&params.tag)
        .map_err(|e| AdapterError::Format(format!("Invalid tag hex: {e}")))?;

    let mut db_ciphertext = BASE64
        .decode(db_base64.trim())
        .map_err(|e| AdapterError::Format(format!("Invalid base64 in db payload: {e}")))?;
    db_ciphertext.extend_from_slice(&tag_bytes);

    let cipher = Aes256Gcm::new_from_slice(&master_key)
        .map_err(|e| AdapterError::Decryption(e.to_string()))?;

    let nonce = Nonce::from_slice(&nonce_bytes);
    let decrypted_bytes = cipher
        .decrypt(nonce, db_ciphertext.as_ref())
        .map_err(|_| AdapterError::Decryption("Failed to decrypt database payload".to_string()))?;

    master_key.zeroize();

    String::from_utf8(decrypted_bytes)
        .map_err(|e| AdapterError::Format(format!("Decrypted data is not valid UTF-8: {e}")))
}
