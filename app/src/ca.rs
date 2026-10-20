//! Local root CA for TLS interception.
//!
//! The app decrypts HTTPS only for the sites and programs the user picked,
//! presenting certificates signed by this CA, which the user must trust once.
//! The certificate lives in `%LOCALAPPDATA%\piikey\ca.crt` (PEM); the private
//! key in `ca.key`, wrapped with DPAPI for the current Windows user, so a copy
//! of the folder is useless on another account or machine.

use std::{
    fmt, fs,
    path::Path,
    process::Output,
    time::{SystemTime, UNIX_EPOCH},
};

use hudsucker::rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair, KeyUsagePurpose,
    date_time_ymd,
};
use windows_dpapi::{Scope, decrypt_data, encrypt_data};

use crate::{
    Res,
    policy::{data_dir, run_system_tool, write_atomic},
};

/// Subject common name; also how `certutil` finds the certificate.
// The name is kept for existing installs: the installed `ca.crt` and the Windows Root store entry carry it.
const CA_NAME: &str = "piikey Guard CA";
/// DPAPI entropy: binds the wrapped key to this purpose and format version.
// Kept for existing installs: changing it makes the wrapped `ca.key` unreadable.
const DPAPI_ENTROPY: &[u8] = b"piikey guard ca v1";
const CERT_FILE: &str = "ca.crt";
const KEY_FILE: &str = "ca.key";
const VALID_YEARS: i32 = 10;
/// Seconds in a day.
const DAY: u64 = 86_400;

/// CA certificate PEM and its private key PEM (decrypted).
pub struct Ca {
    pub cert_pem: String,
    pub key_pem: String,
}

/// Never prints the key: this ends up in logs.
impl fmt::Debug for Ca {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Ca").finish_non_exhaustive()
    }
}

/// Loads or creates the CA under `%LOCALAPPDATA%\piikey`.
///
/// # Errors
/// I/O, DPAPI or certificate generation failure.
pub fn ensure() -> Res<Ca> {
    ensure_in(&data_dir()?)
}

/// Whether the CA is in the current user's Root store.
///
/// Matches by name, so a certificate of an earlier CA with the same name
/// counts; the CA is only ever replaced by deleting its files by hand.
#[must_use]
pub fn is_installed() -> bool {
    certutil(&["-verifystore", "Root", CA_NAME]).is_ok_and(|out| out.status.success())
}

/// Adds the CA to the current user's Root store (Windows prompts once).
///
/// # Errors
/// certutil failure or user declined.
pub fn install() -> Res<()> {
    // Makes sure the file certutil reads exists.
    ensure()?;
    if is_installed() {
        return Ok(());
    }
    let cert = data_dir()?.join(CERT_FILE);
    let out = certutil(&["-addstore", "Root", &cert.to_string_lossy()])?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "the certificate was not installed (cancelled or blocked): {}",
            summary(&out)
        ))
    }
}

/// Removes the CA from the current user's Root store.
///
/// # Errors
/// certutil failure.
#[allow(
    dead_code,
    reason = "the CA API's counterpart of `install`; the app has no button for it yet"
)]
pub fn uninstall() -> Res<()> {
    if !is_installed() {
        return Ok(());
    }
    let out = certutil(&["-delstore", "Root", CA_NAME])?;
    if out.status.success() {
        Ok(())
    } else {
        Err(format!(
            "the certificate was not removed: {}",
            summary(&out)
        ))
    }
}

/// `certutil -user <args>`.
fn certutil(args: &[&str]) -> Res<Output> {
    let mut full = vec!["-user"];
    full.extend_from_slice(args);
    run_system_tool("certutil.exe", &full)
}

/// The last two lines certutil printed: its verdict and the reason.
fn summary(out: &Output) -> String {
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect();
    lines[lines.len().saturating_sub(2)..].join(" ")
}

fn ensure_in(dir: &Path) -> Res<Ca> {
    let cert_path = dir.join(CERT_FILE);
    let key_path = dir.join(KEY_FILE);
    if cert_path.exists() {
        return load(&cert_path, &key_path);
    }
    // The certificate is written last, so without one the CA was never
    // usable (first run, or a first run that was interrupted): nothing can
    // have been installed, and a stray key is safe to replace.
    let ca = generate()?;
    let wrapped = encrypt_data(ca.key_pem.as_bytes(), Scope::User, Some(DPAPI_ENTROPY))
        .map_err(|e| format!("DPAPI cannot protect the CA key: {e:#}"))?;
    write_atomic(&key_path, &wrapped)?;
    write_atomic(&cert_path, ca.cert_pem.as_bytes())?;
    Ok(ca)
}

fn load(cert_path: &Path, key_path: &Path) -> Res<Ca> {
    let reset = format!(
        "to create a new CA, remove ca.crt and ca.key from {}",
        cert_path.parent().unwrap_or(cert_path).display()
    );
    let cert_pem = fs::read_to_string(cert_path)
        .map_err(|e| format!("cannot read {}: {e}", cert_path.display()))?;
    let wrapped = fs::read(key_path).map_err(|e| {
        format!(
            "cannot read the CA key {}: {e}; {reset}",
            key_path.display()
        )
    })?;
    let key = decrypt_data(&wrapped, Scope::User, Some(DPAPI_ENTROPY))
        .map_err(|e| format!("the CA key cannot be unlocked: {e:#}; {reset}"))?;
    let key_pem = String::from_utf8(key).map_err(|_| format!("the CA key is damaged; {reset}"))?;
    Ok(Ca { cert_pem, key_pem })
}

/// A new self-signed CA, valid from yesterday (clock skew) for ten years.
pub(crate) fn generate() -> Res<Ca> {
    let key = KeyPair::generate().map_err(|e| format!("cannot generate the CA key: {e}"))?;
    let mut subject = DistinguishedName::new();
    subject.push(DnType::CommonName, CA_NAME);
    subject.push(DnType::OrganizationName, "piikey");
    let today = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() / DAY);
    let (from, until) = validity(i64::try_from(today).unwrap_or(0));

    let mut params = CertificateParams::default();
    params.distinguished_name = subject;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = date_time_ymd(from.0, from.1, from.2);
    params.not_after = date_time_ymd(until.0, until.1, until.2);
    let cert = params
        .self_signed(&key)
        .map_err(|e| format!("cannot create the CA certificate: {e}"))?;
    Ok(Ca {
        cert_pem: cert.pem(),
        key_pem: key.serialize_pem(),
    })
}

/// `(year, month, day)` of the day before `today` (days since 1970-01-01) and
/// of the same day [`VALID_YEARS`] later; 29 February becomes the 28th.
fn validity(today: i64) -> ((i32, u8, u8), (i32, u8, u8)) {
    let from = civil_from_days(today - 1);
    let (year, month, day) = civil_from_days(today);
    let day = if (month, day) == (2, 29) { 28 } else { day };
    (from, (year + VALID_YEARS, month, day))
}

/// Calendar date of the day `days` after 1970-01-01 (proleptic Gregorian;
/// Howard Hinnant's `civil_from_days`).
fn civil_from_days(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let day_of_era = z.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (
        i32::try_from(year).unwrap_or(1970),
        u8::try_from(month).unwrap_or(1),
        u8::try_from(day).unwrap_or(1),
    )
}

#[cfg(test)]
mod tests {
    use hudsucker::rcgen::Issuer;

    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("piikey-ca-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let _ = fs::create_dir_all(&dir);
        dir
    }

    #[test]
    fn civil_dates_match_known_days() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
        assert_eq!(civil_from_days(19_723), (2024, 1, 1));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(47_482), (2100, 1, 1));
    }

    #[test]
    fn validity_spans_ten_years_starting_yesterday() {
        let (from, until) = validity(19_723);
        assert_eq!(from, (2023, 12, 31));
        assert_eq!(until, (2034, 1, 1));
    }

    #[test]
    fn validity_never_ends_on_a_missing_leap_day() {
        let (from, until) = validity(11_016); // 2000-02-29
        assert_eq!(from, (2000, 2, 28));
        assert_eq!(until, (2010, 2, 28));
    }

    #[test]
    fn generated_ca_is_a_usable_issuer() -> Res<()> {
        let ca = generate()?;
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.key_pem.contains("PRIVATE KEY"));
        let key = KeyPair::from_pem(&ca.key_pem).map_err(|e| e.to_string())?;
        let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, key).map_err(|e| e.to_string())?;
        // Signs a server certificate the way the proxy does for each site.
        let leaf_key = KeyPair::generate().map_err(|e| e.to_string())?;
        let leaf = CertificateParams::new(vec!["example.com".to_owned()])
            .and_then(|params| params.signed_by(&leaf_key, &issuer))
            .map_err(|e| e.to_string())?;
        assert!(leaf.pem().contains("BEGIN CERTIFICATE"));
        Ok(())
    }

    #[test]
    fn ensure_creates_once_and_reloads_the_same_ca() -> Res<()> {
        let dir = temp_dir("reload");
        let first = ensure_in(&dir)?;
        let second = ensure_in(&dir)?;
        assert_eq!(first.cert_pem, second.cert_pem);
        assert_eq!(first.key_pem, second.key_pem);
        // The key at rest is DPAPI ciphertext, not PEM.
        let at_rest = fs::read(dir.join(KEY_FILE)).map_err(|e| e.to_string())?;
        assert!(!String::from_utf8_lossy(&at_rest).contains("PRIVATE KEY"));
        assert!(!at_rest.is_empty());
        Ok(())
    }

    #[test]
    fn an_interrupted_first_run_is_replaced() -> Res<()> {
        let dir = temp_dir("interrupted");
        // The key was written, the certificate never was.
        fs::write(dir.join(KEY_FILE), b"stray").map_err(|e| e.to_string())?;
        let ca = ensure_in(&dir)?;
        assert_eq!(ensure_in(&dir)?.cert_pem, ca.cert_pem);
        Ok(())
    }

    #[test]
    fn an_unreadable_key_is_reported_not_replaced() -> Res<()> {
        let dir = temp_dir("broken");
        let ca = ensure_in(&dir)?;
        fs::write(dir.join(KEY_FILE), b"not a dpapi blob").map_err(|e| e.to_string())?;
        let err = ensure_in(&dir).err().unwrap_or_default();
        assert!(err.contains("cannot be unlocked"), "{err}");
        assert!(err.contains("remove ca.crt and ca.key"), "{err}");
        let kept = fs::read_to_string(dir.join(CERT_FILE)).map_err(|e| e.to_string())?;
        assert_eq!(kept, ca.cert_pem, "the certificate must be left alone");
        Ok(())
    }

    #[test]
    fn a_missing_key_next_to_a_certificate_is_reported() -> Res<()> {
        let dir = temp_dir("nokey");
        ensure_in(&dir)?;
        fs::remove_file(dir.join(KEY_FILE)).map_err(|e| e.to_string())?;
        let err = ensure_in(&dir).err().unwrap_or_default();
        assert!(err.contains("CA key"), "{err}");
        Ok(())
    }

    #[test]
    fn debug_output_hides_the_key() {
        let ca = Ca {
            cert_pem: "cert".into(),
            key_pem: "SECRET-KEY".into(),
        };
        let shown = format!("{ca:?}");
        assert!(!shown.contains("SECRET-KEY"), "{shown}");
    }

    #[test]
    fn summary_keeps_the_last_two_lines() {
        let out = Output {
            status: std::process::ExitStatus::default(),
            stdout: b"Root \"Trusted\"\r\nCertUtil: -addstore command FAILED: 0x800704c7\r\n\r\nThe operation was canceled.\r\n".to_vec(),
            stderr: Vec::new(),
        };
        assert_eq!(
            summary(&out),
            "CertUtil: -addstore command FAILED: 0x800704c7 The operation was canceled."
        );
    }
}
