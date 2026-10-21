//! Local root CA for TLS interception.
//!
//! The app decrypts HTTPS only for the sites and programs the user picked,
//! presenting certificates signed by this CA, which the user must trust once.
//! The certificate lives in `%LOCALAPPDATA%\piikey\ca.crt` (PEM); the private
//! key in `ca.key`, wrapped with DPAPI for the current Windows user, so a copy
//! of the folder is useless on another account or machine.

use std::{
    fmt::{self, Write as _},
    fs, mem,
    path::Path,
    process::Output,
    time::{SystemTime, UNIX_EPOCH},
};

use hudsucker::{
    rcgen::{
        BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, KeyPair,
        KeyUsagePurpose, date_time_ymd,
    },
    rustls::pki_types::{CertificateDer, pem::PemObject},
};
use piikey::sys::{data_dir, dpapi_protect, dpapi_unprotect, run_system_tool, write_atomic};
use zeroize::{Zeroize, Zeroizing};

use crate::{Describe, Res};

/// Subject common name.
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

/// CA certificate PEM and its private key PEM (decrypted; wiped when dropped).
pub struct Ca {
    pub cert_pem: String,
    pub key_pem: Zeroizing<String>,
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
    ensure_in(&data_dir().describe()?)
}

/// Whether this CA (the certificate in `ca.crt`) is in the current user's Root store. It is found
/// by its serial number, not by its name: when `ca.crt` and `ca.key` were deleted by hand to make
/// a new CA, the one they replace has the same name, and trusting that one would leave the new
/// CA untrusted: every protected site would fail with a certificate error.
#[must_use]
pub fn is_installed() -> bool {
    let Ok(dir) = data_dir() else {
        return false;
    };
    let Ok(pem) = fs::read_to_string(dir.join(CERT_FILE)) else {
        return false;
    };
    certificate_id(&pem).is_some_and(|id| {
        certutil(&["-verifystore", "Root", &id]).is_ok_and(|out| out.status.success())
    })
}

/// What `certutil` takes to find a certificate in a store: its serial number in hex. A serial
/// that is digits only reads as a position in the store to certutil, so the name stands in.
fn certificate_id(pem: &str) -> Option<String> {
    let der = CertificateDer::from_pem_slice(pem.as_bytes()).ok()?;
    let mut id = String::new();
    for byte in serial_number(&der)? {
        let _ = write!(id, "{byte:02x}");
    }
    Some(if id.bytes().all(|digit| digit.is_ascii_digit()) {
        CA_NAME.to_owned()
    } else {
        id
    })
}

/// The serial number of a DER certificate: the first field of its `TBSCertificate`, after the
/// version when there is one.
fn serial_number(cert: &[u8]) -> Option<&[u8]> {
    let (0x30, cert, _) = der_element(cert)? else {
        return None;
    };
    let (0x30, tbs, _) = der_element(cert)? else {
        return None;
    };
    let (mut tag, mut serial, rest) = der_element(tbs)?;
    if tag == 0xA0 {
        (tag, serial, _) = der_element(rest)?;
    }
    (tag == 0x02).then_some(serial)
}

/// The tag, the content and the rest of the first DER element of `der`.
fn der_element(der: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (&tag, rest) = der.split_first()?;
    let (&first, rest) = rest.split_first()?;
    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        // A length of its own bytes; the indefinite form (`0x80`) has no place in DER.
        let count = usize::from(first & 0x7F);
        if count == 0 || count > size_of::<usize>() || rest.len() < count {
            return None;
        }
        let (bytes, rest) = rest.split_at(count);
        let length = bytes
            .iter()
            .fold(0_usize, |length, &byte| (length << 8) | usize::from(byte));
        (length, rest)
    };
    (rest.len() >= length).then(|| (tag, &rest[..length], &rest[length..]))
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
    let cert = data_dir().describe()?.join(CERT_FILE);
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

/// `certutil -user <args>`.
fn certutil(args: &[&str]) -> Res<Output> {
    let mut full = vec!["-user"];
    full.extend_from_slice(args);
    run_system_tool("certutil.exe", &full).describe()
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
    let wrapped = dpapi_protect(ca.key_pem.as_bytes(), DPAPI_ENTROPY)
        .map_err(|e| format!("the CA key cannot be protected: {e}"))?;
    write_atomic(&key_path, &wrapped).describe()?;
    write_atomic(&cert_path, ca.cert_pem.as_bytes()).describe()?;
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
    let mut key = dpapi_unprotect(&wrapped, DPAPI_ENTROPY)
        .map_err(|e| format!("the CA key cannot be unlocked: {e}; {reset}"))?;
    // The PEM text takes over the decrypted bytes: no second copy of the key is left behind.
    let key_pem = String::from_utf8(mem::take(&mut *key)).map_err(|e| {
        e.into_bytes().zeroize();
        format!("the CA key is damaged; {reset}")
    })?;
    Ok(Ca {
        cert_pem,
        key_pem: Zeroizing::new(key_pem),
    })
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
        key_pem: Zeroizing::new(key.serialize_pem()),
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
    use hudsucker::rcgen::{Issuer, SerialNumber};

    use super::*;

    fn temp_dir(tag: &str) -> std::path::PathBuf {
        crate::ui::testing::temp_dir(tag)
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
        let key = KeyPair::from_pem(&ca.key_pem).describe()?;
        let issuer = Issuer::from_ca_cert_pem(&ca.cert_pem, key).describe()?;
        // Signs a server certificate the way the proxy does for each site.
        let leaf_key = KeyPair::generate().describe()?;
        let leaf = CertificateParams::new(vec!["example.com".to_owned()])
            .and_then(|params| params.signed_by(&leaf_key, &issuer))
            .describe()?;
        assert!(leaf.pem().contains("BEGIN CERTIFICATE"));
        Ok(())
    }

    /// A self-signed certificate with this serial number, as PEM.
    fn pem_with_serial(serial: &[u8]) -> Res<String> {
        let key = KeyPair::generate().describe()?;
        let mut params = CertificateParams::default();
        params.serial_number = Some(SerialNumber::from_slice(serial));
        let cert = params.self_signed(&key).describe()?;
        Ok(cert.pem())
    }

    #[test]
    fn a_certificate_is_found_by_its_serial_number() -> Res<()> {
        let id = certificate_id(&pem_with_serial(&[0x12, 0xAB, 0x00, 0xCD])?);
        assert_eq!(id.as_deref(), Some("12ab00cd"));
        // Digits only would read as a position in the store: the name stands in.
        let id = certificate_id(&pem_with_serial(&[0x12, 0x34])?);
        assert_eq!(id.as_deref(), Some(CA_NAME));
        Ok(())
    }

    #[test]
    fn two_cas_of_the_same_name_have_different_ids() -> Res<()> {
        let (first, second) = (generate()?, generate()?);
        let (first, second) = (
            certificate_id(&first.cert_pem),
            certificate_id(&second.cert_pem),
        );
        assert!(first.is_some() && second.is_some());
        assert_ne!(
            first, second,
            "an older CA's entry in the store must not stand in"
        );
        Ok(())
    }

    #[test]
    fn a_damaged_certificate_has_no_id() {
        assert_eq!(certificate_id("not a certificate"), None);
        let damaged: [&[u8]; 5] = [
            &[],
            &[0x30],
            &[0x30, 0x80, 0x00],
            &[0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF],
            &[0x30, 0x03, 0x30, 0x01, 0x02],
        ];
        for der in damaged {
            assert_eq!(serial_number(der), None, "{der:02x?}");
        }
    }

    #[test]
    fn ensure_creates_once_and_reloads_the_same_ca() -> Res<()> {
        let dir = temp_dir("reload");
        let first = ensure_in(&dir)?;
        let second = ensure_in(&dir)?;
        assert_eq!(first.cert_pem, second.cert_pem);
        assert_eq!(*first.key_pem, *second.key_pem);
        // The key at rest is DPAPI ciphertext, not PEM.
        let at_rest = fs::read(dir.join(KEY_FILE)).describe()?;
        assert!(!String::from_utf8_lossy(&at_rest).contains("PRIVATE KEY"));
        assert!(!at_rest.is_empty());
        Ok(())
    }

    #[test]
    fn an_interrupted_first_run_is_replaced() -> Res<()> {
        let dir = temp_dir("interrupted");
        // The key was written, the certificate never was.
        fs::write(dir.join(KEY_FILE), b"stray").describe()?;
        let ca = ensure_in(&dir)?;
        assert_eq!(ensure_in(&dir)?.cert_pem, ca.cert_pem);
        Ok(())
    }

    #[test]
    fn an_unreadable_key_is_reported_not_replaced() -> Res<()> {
        let dir = temp_dir("broken");
        let ca = ensure_in(&dir)?;
        fs::write(dir.join(KEY_FILE), b"not a dpapi blob").describe()?;
        let err = ensure_in(&dir).err().unwrap_or_default();
        assert!(err.contains("cannot be unlocked"), "{err}");
        assert!(err.contains("remove ca.crt and ca.key"), "{err}");
        let kept = fs::read_to_string(dir.join(CERT_FILE)).describe()?;
        assert_eq!(kept, ca.cert_pem, "the certificate must be left alone");
        Ok(())
    }

    #[test]
    fn a_missing_key_next_to_a_certificate_is_reported() -> Res<()> {
        let dir = temp_dir("nokey");
        ensure_in(&dir)?;
        fs::remove_file(dir.join(KEY_FILE)).describe()?;
        let err = ensure_in(&dir).err().unwrap_or_default();
        assert!(err.contains("CA key"), "{err}");
        Ok(())
    }

    #[test]
    fn debug_output_hides_the_key() {
        let ca = Ca {
            cert_pem: "cert".into(),
            key_pem: Zeroizing::new("SECRET-KEY".into()),
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
