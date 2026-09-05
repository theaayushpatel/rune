use crate::models::{Algorithm, OtpAccount, OtpType};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroize;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum OtpError {
    #[error("Invalid Base32 secret: {0}")]
    InvalidBase32(String),
    #[error("Unsupported number of digits: {0} (must be between 4 and 10)")]
    InvalidDigits(u32),
    #[error("Period must be greater than 0")]
    InvalidPeriod,
    #[error("HOTP missing counter")]
    MissingCounter,
    #[error("System clock error: {0}")]
    ClockError(String),
}

/// Decode a Base32 secret string (RFC 4648), handling case-insensitivity,
/// spaces, hyphens, and optional padding.
pub fn decode_secret(secret_str: &str) -> Result<Vec<u8>, OtpError> {
    // Strip whitespace, hyphens, and '=' padding
    let cleaned: String = secret_str
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-' && *c != '=')
        .map(|c| c.to_ascii_uppercase())
        .collect();

    if cleaned.is_empty() {
        return Err(OtpError::InvalidBase32("Secret is empty".to_string()));
    }

    BASE32_NOPAD
        .decode(cleaned.as_bytes())
        .map_err(|e| OtpError::InvalidBase32(e.to_string()))
}

/// Compute HMAC using the specified algorithm and secret.
fn compute_hmac(algorithm: Algorithm, secret: &[u8], counter: u64) -> Vec<u8> {
    let counter_bytes = counter.to_be_bytes();
    match algorithm {
        Algorithm::SHA1 => {
            let mut mac = Hmac::<Sha1>::new_from_slice(secret)
                .expect("HMAC can take key of any size");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::SHA256 => {
            let mut mac = Hmac::<Sha256>::new_from_slice(secret)
                .expect("HMAC can take key of any size");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
        Algorithm::SHA512 => {
            let mut mac = Hmac::<Sha512>::new_from_slice(secret)
                .expect("HMAC can take key of any size");
            mac.update(&counter_bytes);
            mac.finalize().into_bytes().to_vec()
        }
    }
}

/// Generate an HOTP code (RFC 4226) for a given counter value.
pub fn generate_hotp(
    secret: &[u8],
    counter: u64,
    digits: u32,
    algorithm: Algorithm,
) -> Result<String, OtpError> {
    if !(4..=10).contains(&digits) {
        return Err(OtpError::InvalidDigits(digits));
    }

    let hmac_result = compute_hmac(algorithm, secret, counter);
    let offset = (hmac_result[hmac_result.len() - 1] & 0x0f) as usize;

    let binary = ((hmac_result[offset] as u32 & 0x7f) << 24)
        | ((hmac_result[offset + 1] as u32 & 0xff) << 16)
        | ((hmac_result[offset + 2] as u32 & 0xff) << 8)
        | (hmac_result[offset + 3] as u32 & 0xff);

    let modulo = 10u32.pow(digits);
    let code = binary % modulo;

    Ok(format!("{:0width$}", code, width = digits as usize))
}

/// Generate a TOTP code (RFC 6238) for a given unix timestamp.
pub fn generate_totp(
    secret: &[u8],
    timestamp: u64,
    period: u32,
    digits: u32,
    algorithm: Algorithm,
) -> Result<String, OtpError> {
    if period == 0 {
        return Err(OtpError::InvalidPeriod);
    }
    let counter = timestamp / (period as u64);
    generate_hotp(secret, counter, digits, algorithm)
}

/// Generate current code for an `OtpAccount`.
pub fn generate_account_code(account: &OtpAccount, timestamp: Option<u64>) -> Result<String, OtpError> {
    let ts = match timestamp {
        Some(t) => t,
        None => SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| OtpError::ClockError(e.to_string()))?
            .as_secs(),
    };

    let mut raw_secret = decode_secret(&account.secret)?;
    let result = match account.otp_type {
        OtpType::Totp => generate_totp(
            &raw_secret,
            ts,
            account.period,
            account.digits,
            account.algorithm,
        ),
        OtpType::Hotp => {
            let counter = account.counter.ok_or(OtpError::MissingCounter)?;
            generate_hotp(&raw_secret, counter, account.digits, account.algorithm)
        }
    };

    // Zeroize memory containing the raw cryptographic secret bytes
    raw_secret.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 6238 Test Vector secret: "12345678901234567890" in ASCII
    // Base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
    const RFC_SECRET_BASE32: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

    #[test]
    fn test_rfc6238_sha1_vectors() {
        let secret = decode_secret(RFC_SECRET_BASE32).unwrap();

        // 8-digit codes from RFC 6238 Appendix B
        assert_eq!(
            generate_totp(&secret, 59, 30, 8, Algorithm::SHA1).unwrap(),
            "94287082"
        );
        assert_eq!(
            generate_totp(&secret, 1111111109, 30, 8, Algorithm::SHA1).unwrap(),
            "07081804"
        );
        assert_eq!(
            generate_totp(&secret, 1111111111, 30, 8, Algorithm::SHA1).unwrap(),
            "14050471"
        );
        assert_eq!(
            generate_totp(&secret, 1234567890, 30, 8, Algorithm::SHA1).unwrap(),
            "89005924"
        );
        assert_eq!(
            generate_totp(&secret, 2000000000, 30, 8, Algorithm::SHA1).unwrap(),
            "69279037"
        );

        // 6-digit codes
        assert_eq!(
            generate_totp(&secret, 1111111109, 30, 6, Algorithm::SHA1).unwrap(),
            "081804"
        );
        assert_eq!(
            generate_totp(&secret, 1234567890, 30, 6, Algorithm::SHA1).unwrap(),
            "005924"
        );
    }

    #[test]
    fn test_rfc6238_sha256_and_sha512_vectors() {
        let sha256_secret = b"12345678901234567890123456789012";
        assert_eq!(
            generate_totp(sha256_secret, 59, 30, 8, Algorithm::SHA256).unwrap(),
            "46119246"
        );
        assert_eq!(
            generate_totp(sha256_secret, 1111111109, 30, 8, Algorithm::SHA256).unwrap(),
            "68084774"
        );
        assert_eq!(
            generate_totp(sha256_secret, 1111111111, 30, 8, Algorithm::SHA256).unwrap(),
            "67062674"
        );
        assert_eq!(
            generate_totp(sha256_secret, 1234567890, 30, 8, Algorithm::SHA256).unwrap(),
            "91819424"
        );
        assert_eq!(
            generate_totp(sha256_secret, 2000000000, 30, 8, Algorithm::SHA256).unwrap(),
            "90698825"
        );

        let sha512_secret = b"1234567890123456789012345678901234567890123456789012345678901234";
        assert_eq!(
            generate_totp(sha512_secret, 59, 30, 8, Algorithm::SHA512).unwrap(),
            "90693936"
        );
        assert_eq!(
            generate_totp(sha512_secret, 1111111109, 30, 8, Algorithm::SHA512).unwrap(),
            "25091201"
        );
        assert_eq!(
            generate_totp(sha512_secret, 1111111111, 30, 8, Algorithm::SHA512).unwrap(),
            "99943326"
        );
        assert_eq!(
            generate_totp(sha512_secret, 1234567890, 30, 8, Algorithm::SHA512).unwrap(),
            "93441116"
        );
        assert_eq!(
            generate_totp(sha512_secret, 2000000000, 30, 8, Algorithm::SHA512).unwrap(),
            "38618901"
        );
    }

    #[test]
    fn test_rfc4226_hotp_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            "755224", "287082", "359152", "969429", "338314",
            "254676", "287922", "162583", "399871", "520489",
        ];

        for (count, exp) in expected.iter().enumerate() {
            let code = generate_hotp(secret, count as u64, 6, Algorithm::SHA1).unwrap();
            assert_eq!(&code, exp, "HOTP failed for count {}", count);
        }
    }

    #[test]
    fn test_secret_cleaning() {
        // Hyphens, lowercase, spaces, padding
        let s1 = "gez-dgnb vgy3-tqoj qgez-dgnb vgy3-tqoj q===";
        let decoded1 = decode_secret(s1).unwrap();
        let decoded2 = decode_secret(RFC_SECRET_BASE32).unwrap();
        assert_eq!(decoded1, decoded2);
    }
}

