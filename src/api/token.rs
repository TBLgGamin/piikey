//! The token the HTTP API wants as `Authorization: Bearer <token>`.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use crate::{
    Result,
    sys::{self, io_context},
};

/// The token's file in the data folder.
const TOKEN_FILE: &str = "api.token";
/// A token is this many random bytes, written in hex.
const TOKEN_BYTES: usize = 32;
/// A token on file shorter than this is not one piikey made (or someone cut it): it is replaced.
const MIN_TOKEN: usize = 32;

/// Where the token is kept: `%LOCALAPPDATA%\piikey\api.token`.
fn token_path() -> Result<PathBuf> {
    Ok(sys::data_dir()?.join(TOKEN_FILE))
}

/// The token the HTTP API wants as `Authorization: Bearer <token>`: 32 random bytes in hex, kept
/// in `%LOCALAPPDATA%\piikey\api.token`. It is made the first time it is asked for, and again
/// when `rotate` says so. A running HTTP server keeps the token it was started with, so start it
/// again after a rotation.
///
/// # Errors
/// `VaultPathUnavailable` when `LOCALAPPDATA` is unset; `Io` when the token cannot be read or
/// written, or no random bytes can be had.
pub fn read_or_create_token(rotate: bool) -> Result<String> {
    token_in(&token_path()?, rotate)
}

fn token_in(path: &Path, rotate: bool) -> Result<String> {
    if !rotate {
        match fs::read_to_string(path) {
            Ok(text) => {
                let token = text.trim();
                if token.len() >= MIN_TOKEN && token.bytes().all(|byte| byte.is_ascii_graphic()) {
                    return Ok(token.to_owned());
                }
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(io_context(&e, "read", path)),
        }
    }
    let mut bytes = [0_u8; TOKEN_BYTES];
    sys::fill_random(&mut bytes)?;
    let token = hex(&bytes);
    sys::write_atomic(path, token.as_bytes())?;
    Ok(token)
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0xF)]));
    }
    out
}

#[cfg(test)]
mod tests {
    use std::error::Error as StdError;

    use super::*;

    type TestResult = std::result::Result<(), Box<dyn StdError>>;

    #[test]
    fn the_token_is_made_once_and_replaced_on_request() -> TestResult {
        let path = crate::testing::temp_dir("token").join("api.token");
        let first = token_in(&path, false)?;
        assert_eq!(first.len(), TOKEN_BYTES * 2);
        assert!(first.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(token_in(&path, false)?, first);
        let second = token_in(&path, true)?;
        assert_ne!(second, first);
        assert_eq!(token_in(&path, false)?, second);
        // A file that is no token (cut short, edited) is replaced.
        fs::write(&path, "abc")?;
        let third = token_in(&path, false)?;
        assert_eq!(third.len(), TOKEN_BYTES * 2);
        assert_eq!(fs::read_to_string(&path)?, third);
        Ok(())
    }

    #[test]
    fn hex_writes_two_lowercase_digits_per_byte() {
        assert_eq!(hex(&[0x00, 0x0F, 0xA5, 0xFF]), "000fa5ff");
        assert_eq!(hex(&[]), "");
    }
}
