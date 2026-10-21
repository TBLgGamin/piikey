//! Download of the detection model, for the app's first run and for `piikey-cli model download`.
//!
//! `curl.exe` and `certutil.exe` ship with Windows, so no HTTP or hashing crate is needed.
//! curl ignores the `WinINET` proxy setting, so the download never loops through piikey itself.

use std::{fs, io::Read, path::Path, process::Stdio, thread, time::Duration};

use super::files::{FILES, ModelFile, VERIFIED};
use crate::{
    Error, Result,
    sys::{io_context, system_command, write_atomic},
};

/// How often the running download reports progress.
const POLL: Duration = Duration::from_millis(200);

/// Downloads every model file into `dir`, checks their hashes and marks the folder verified.
/// `progress(done, total)` is called with byte counts while it runs. Files that are already
/// complete are not downloaded again, and partial ones resume.
///
/// # Errors
/// `Model` when the download failed or a file came out damaged (it is deleted so a retry starts
/// over); `Tool` when `curl.exe` or `certutil.exe` cannot be run, or certutil cannot hash a file
/// (which stays: nothing is known against it); `Io` when a file cannot be written.
pub fn fetch(dir: &Path, progress: &dyn Fn(u64, u64)) -> Result<()> {
    fs::create_dir_all(dir).map_err(|e| io_context(&e, "create", dir))?;
    let total: u64 = FILES.iter().map(|file| file.size).sum();
    let mut done = 0;
    for file in &FILES {
        download(dir, file, done, total, progress)?;
        done += file.size;
        progress(done, total);
    }
    for file in &FILES {
        verify(dir, file)?;
    }
    write_atomic(&dir.join(VERIFIED), b"")
}

/// Brings `dir/file.name` to its full size, resuming a `.part` file.
fn download(
    dir: &Path,
    file: &ModelFile,
    done: u64,
    total: u64,
    progress: &dyn Fn(u64, u64),
) -> Result<()> {
    let target = dir.join(file.name);
    if size_of(&target) == Some(file.size) {
        return Ok(());
    }
    let part = dir.join(format!("{}.part", file.name));
    if size_of(&part) != Some(file.size) {
        run_curl(&part, file, done, total, progress)?;
    }
    if size_of(&part) != Some(file.size) {
        // A server that sent more or less than expected: start that file over next time.
        let _ = fs::remove_file(&part);
        return Err(damaged());
    }
    // The marker vouches for the files as they were when it was written, and this one is new:
    // until `fetch` has hashed it, the folder is not installed, so that an unchecked file is
    // never taken for a checked one.
    let _ = fs::remove_file(dir.join(VERIFIED));
    fs::rename(&part, &target).map_err(|e| io_context(&e, "write", &target))
}

/// Runs `curl.exe` until `part` holds what the server has, resuming what is there, and reports
/// the progress of the whole download while it does (`done` bytes came before this file).
fn run_curl(
    part: &Path,
    file: &ModelFile,
    done: u64,
    total: u64,
    progress: &dyn Fn(u64, u64),
) -> Result<()> {
    let mut child = system_command("curl.exe")?
        .args([
            "--location",
            "--fail",
            "--silent",
            "--show-error",
            "--retry",
            "3",
            "--continue-at",
            "-",
            "--output",
        ])
        .arg(part)
        .arg(file.url)
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| Error::Tool(format!("cannot run curl.exe: {e}")))?;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                progress(done + size_of(part).unwrap_or(0).min(file.size), total);
                thread::sleep(POLL);
            }
            Err(e) => return Err(Error::Tool(format!("cannot watch curl.exe: {e}"))),
        }
    };
    if status.success() {
        return Ok(());
    }
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    Err(Error::Model(format!(
        "could not download the files: {}",
        stderr.trim()
    )))
}

/// Compares the SHA-256 of `dir/file.name` with the pinned one. Deletes the file on a mismatch
/// and only then: when certutil cannot read the file (something else holds it, say) nothing is
/// known against it, and a download of 300 MB is worth keeping.
fn verify(dir: &Path, file: &ModelFile) -> Result<()> {
    let path = dir.join(file.name);
    let out = system_command("certutil.exe")?
        .arg("-hashfile")
        .arg(&path)
        .arg("SHA256")
        .output()
        .map_err(|e| Error::Tool(format!("cannot run certutil.exe: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    match out.status.success().then(|| certutil_hash(&text)).flatten() {
        Some(hash) if hash == file.sha256 => Ok(()),
        Some(_) => {
            let _ = fs::remove_file(&path);
            Err(damaged())
        }
        None => {
            let reason = text.lines().rev().find(|line| !line.trim().is_empty());
            Err(Error::Tool(format!(
                "certutil.exe could not hash {}: {}",
                file.name,
                reason.map_or("no answer", str::trim)
            )))
        }
    }
}

fn damaged() -> Error {
    Error::Model("the downloaded files were damaged; try again".to_owned())
}

/// The hash in `certutil -hashfile` output: the second line, spaces removed, lowercased.
fn certutil_hash(output: &str) -> Option<String> {
    let line = output.lines().nth(1)?;
    let hash: String = line
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| c.to_ascii_lowercase())
        .collect();
    (hash.len() == 64 && hash.bytes().all(|b| b.is_ascii_hexdigit())).then_some(hash)
}

fn size_of(path: &Path) -> Option<u64> {
    fs::metadata(path).ok().map(|meta| meta.len())
}

#[cfg(test)]
mod tests {
    use std::{io::Write, os::windows::fs::OpenOptionsExt};

    use super::*;
    use crate::detect::ner::files::Scratch;

    /// A file of three bytes, for the steps that never reach the network.
    const SMALL: ModelFile = ModelFile {
        name: "a.bin",
        url: "",
        size: 3,
        sha256: "",
    };

    #[test]
    fn the_hash_is_read_from_both_certutil_layouts() {
        // Older Windows prints the hash with a space between byte pairs.
        let spaced = "SHA256 hash of x:\r\n1e e9 75 af 53 7a 3a e5 07 76 97 03 c0 3f c8 38 80 cc e7 e2 70 6b c6 d2 dc 1f d9 db 86 1a cf a1\r\nCertUtil: -hashfile command completed successfully.\r\n";
        let plain = "SHA256 hash of x:\n1EE975AF537A3AE507769703C03FC83880CCE7E2706BC6D2DC1FD9DB861ACFA1\nCertUtil: done\n";
        let want = "1ee975af537a3ae507769703c03fc83880cce7e2706bc6d2dc1fd9db861acfa1";
        assert_eq!(certutil_hash(spaced).as_deref(), Some(want));
        assert_eq!(certutil_hash(plain).as_deref(), Some(want));
        assert_eq!(
            certutil_hash("CertUtil: error\nThe system cannot find the file.\n"),
            None
        );
    }

    #[test]
    fn a_damaged_file_is_deleted_and_reported() -> Result<()> {
        let scratch = Scratch::new("damaged");
        let file = &FILES[1];
        fs::write(scratch.0.join(file.name), b"not the tokenizer")?;
        let result = verify(&scratch.0, file);
        assert!(matches!(result, Err(Error::Model(_))), "{result:?}");
        assert!(!scratch.0.join(file.name).exists());
        Ok(())
    }

    #[test]
    fn a_file_certutil_cannot_read_is_kept_and_not_called_damaged() -> Result<()> {
        let scratch = Scratch::new("locked");
        let file = &FILES[1];
        let path = scratch.0.join(file.name);
        // Created and held without sharing, as a scanner can hold a file: certutil is refused,
        // which says nothing about what the file holds. Holding it from the start leaves no
        // moment for a scanner of this machine to open it first.
        let mut held = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .share_mode(0)
            .open(&path)?;
        held.write_all(b"whatever it holds")?;
        let result = verify(&scratch.0, file);
        drop(held);
        assert!(matches!(result, Err(Error::Tool(_))), "{result:?}");
        assert!(path.exists(), "a file nobody checked is not deleted");
        Ok(())
    }

    #[test]
    fn a_file_that_comes_in_takes_the_verified_marker_with_it() -> Result<()> {
        let scratch = Scratch::new("marker");
        let dir = &scratch.0;
        fs::write(dir.join(VERIFIED), b"")?;
        // A download that was cut off after its last byte: only the rename is left.
        fs::write(dir.join("a.bin.part"), [0u8; 3])?;
        download(dir, &SMALL, 0, SMALL.size, &|_, _| {})?;
        assert!(dir.join("a.bin").is_file());
        assert!(!dir.join("a.bin.part").exists());
        assert!(
            !dir.join(VERIFIED).exists(),
            "the marker said nothing about this file"
        );

        // A file that is in place already changes nothing, the marker included.
        fs::write(dir.join(VERIFIED), b"")?;
        download(dir, &SMALL, 0, SMALL.size, &|_, _| {})?;
        assert!(dir.join(VERIFIED).is_file());
        Ok(())
    }
}
