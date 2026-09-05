use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use rune_core::source::AdapterError;
use zeroize::Zeroize;

const PBKDF2_ITERATIONS: u32 = 10_000;
const AUTH_TAG_LEN: usize = 16;

/// Decrypt the 2FAS encrypted payload (`servicesEncrypted` or `reference`).
///
/// Format: `<base64_ciphertext_with_tag>:<base64_salt>:<base64_iv>`
pub fn decrypt_2fas_payload(encrypted_field: &str, password: &str) -> Result<String, AdapterError> {
    let parts: Vec<&str> = encrypted_field.split(':').collect();
    if parts.len() != 3 {
        return Err(AdapterError::Format(format!(
            "Invalid 2FAS encrypted field format: expected 3 colon-separated tokens, found {}",
            parts.len()
        )));
    }

    let ciphertext_with_tag = BASE64
        .decode(parts[0].trim())
        .map_err(|e| AdapterError::Format(format!("Invalid base64 ciphertext: {e}")))?;

    if ciphertext_with_tag.len() <= AUTH_TAG_LEN {
        return Err(AdapterError::Format(format!(
            "Invalid 2FAS ciphertext length ({} bytes), must exceed auth tag length ({} bytes)",
            ciphertext_with_tag.len(),
            AUTH_TAG_LEN
        )));
    }

    let salt = BASE64
        .decode(parts[1].trim())
        .map_err(|e| AdapterError::Format(format!("Invalid base64 salt: {e}")))?;

    let iv = BASE64
        .decode(parts[2].trim())
        .map_err(|e| AdapterError::Format(format!("Invalid base64 IV: {e}")))?;

    if iv.len() != 12 {
        return Err(AdapterError::Format(format!(
            "Invalid 2FAS IV length: expected 12 bytes, got {}",
            iv.len()
        )));
    }

    // 1. Derive 32-byte key using PBKDF2-HMAC-SHA256 (10,000 iterations)
    let mut derived_key = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<sha2::Sha256>(
        password.as_bytes(),
        &salt,
        PBKDF2_ITERATIONS,
        &mut derived_key,
    );

    // 2. Decrypt AES-256-GCM
    let cipher = Aes256Gcm::new_from_slice(&derived_key)
        .map_err(|e| AdapterError::Decryption(e.to_string()))?;

    let nonce = Nonce::from_slice(&iv);
    let decrypt_result = cipher.decrypt(nonce, ciphertext_with_tag.as_ref());

    derived_key.zeroize();

    let decrypted_bytes = decrypt_result.map_err(|_| AdapterError::InvalidPassword)?;

    String::from_utf8(decrypted_bytes)
        .map_err(|e| AdapterError::Format(format!("Decrypted 2FAS data is not valid UTF-8: {e}")))
}
