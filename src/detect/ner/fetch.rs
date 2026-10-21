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
/// over); `Tool` when `curl.exe` or `certutil.exe` cannot be run; `Io` when a file cannot be
/// written.
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
            .arg(&part)
            .arg(file.url)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Tool(format!("cannot run curl.exe: {e}")))?;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {
                    progress(done + size_of(&part).unwrap_or(0).min(file.size), total);
                    thread::sleep(POLL);
                }
                Err(e) => return Err(Error::Tool(format!("cannot watch curl.exe: {e}"))),
            }
        };
        if !status.success() {
            let mut stderr = String::new();
            if let Some(mut pipe) = child.stderr.take() {
                let _ = pipe.read_to_string(&mut stderr);
            }
            return Err(Error::Model(format!(
                "could not download the files: {}",
                stderr.trim()
            )));
        }
    }
    if size_of(&part) != Some(file.size) {
        // A server that sent more or less than expected: start that file over next time.
        let _ = fs::remove_file(&part);
        return Err(damaged());
    }
    fs::rename(&part, &target).map_err(|e| io_context(&e, "write", &target))
}

/// Compares the SHA-256 of `dir/file.name` with the pinned one; deletes the file on a mismatch.
fn verify(dir: &Path, file: &ModelFile) -> Result<()> {
    let path = dir.join(file.name);
    let out = system_command("certutil.exe")?
        .arg("-hashfile")
        .arg(&path)
        .arg("SHA256")
        .output()
        .map_err(|e| Error::Tool(format!("cannot run certutil.exe: {e}")))?;
    let text = String::from_utf8_lossy(&out.stdout);
    if out.status.success() && certutil_hash(&text).as_deref() == Some(file.sha256) {
        return Ok(());
    }
    let _ = fs::remove_file(&path);
    Err(damaged())
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
    use super::*;

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
        let dir = std::env::temp_dir().join(format!("piikey-model-{}", std::process::id()));
        fs::create_dir_all(&dir)?;
        let file = &FILES[1];
        fs::write(dir.join(file.name), b"not the tokenizer")?;
        let result = verify(&dir, file);
        assert!(matches!(result, Err(Error::Model(_))), "{result:?}");
        assert!(!dir.join(file.name).exists());
        fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
