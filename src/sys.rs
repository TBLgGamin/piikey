//! Windows plumbing the CLI, the API and the app share: the data folder, atomic file writes and
//! the tools that ship in System32.

use std::{
    fs::{self, File},
    io::{self, Write},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

use crate::{Error, Result};

/// `CREATE_NO_WINDOW`: console tools run from the GUI must not flash a window.
pub const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `%LOCALAPPDATA%\piikey` (created): the vault, the settings, the certificate, the model and the
/// inventory live here.
///
/// # Errors
/// `VaultPathUnavailable` when `LOCALAPPDATA` is unset; `Io` when the folder cannot be created.
pub fn data_dir() -> Result<PathBuf> {
    let base = std::env::var_os("LOCALAPPDATA")
        .filter(|base| !base.is_empty())
        .ok_or(Error::VaultPathUnavailable)?;
    let dir = PathBuf::from(base).join("piikey");
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Writes `bytes` to a temp file beside `path`, syncs it and renames it over `path`, so readers
/// see the old or the new file, never a torn one.
///
/// # Errors
/// `Io` on any I/O failure, naming `path`; the temp file is removed.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let written = File::create(&tmp)
        .and_then(|mut file| {
            file.write_all(bytes)?;
            file.sync_all()
        })
        .and_then(|()| fs::rename(&tmp, path));
    written.map_err(|e| {
        let _ = fs::remove_file(&tmp);
        io_context(&e, "write", path)
    })
}

/// `error` as an [`Error::Io`] that says what was being done to which file ("cannot read
/// C:\...\guard.cfg: Access is denied."). The kind is kept, so callers can still match on it.
pub(crate) fn io_context(error: &io::Error, doing: &str, path: &Path) -> Error {
    Error::Io(io::Error::new(
        error.kind(),
        format!("cannot {doing} {}: {error}", path.display()),
    ))
}

/// A command for `tool` (e.g. `curl.exe`) from `%SystemRoot%\System32` with no console window
/// and stdin closed; the caller adds arguments and pipes.
///
/// # Errors
/// `Tool` when the tool is not in System32.
pub fn system_command(tool: &str) -> Result<Command> {
    let root = std::env::var_os("SystemRoot")
        .filter(|root| !root.is_empty())
        .map_or_else(|| PathBuf::from(r"C:\Windows"), PathBuf::from);
    let path = root.join("System32").join(tool);
    if !path.is_file() {
        return Err(Error::Tool(format!("{tool} was not found in System32")));
    }
    let mut command = Command::new(path);
    command
        .stdin(Stdio::null())
        .creation_flags(CREATE_NO_WINDOW);
    Ok(command)
}

/// Runs `tool` (e.g. `certutil.exe`) from `%SystemRoot%\System32` with no console window and
/// waits for it. A non-zero exit is not an error here; callers read the status.
///
/// # Errors
/// `Tool` when the tool is missing or cannot be started.
pub fn run_system_tool(tool: &str, args: &[&str]) -> Result<Output> {
    system_command(tool)?
        .args(args)
        .output()
        .map_err(|e| Error::Tool(format!("cannot run {tool}: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> Result<PathBuf> {
        let dir = std::env::temp_dir().join(format!("piikey-sys-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir)?;
        Ok(dir)
    }

    #[test]
    fn the_data_dir_is_the_piikey_folder_under_localappdata() -> Result<()> {
        match data_dir() {
            Ok(dir) => {
                assert!(dir.ends_with("piikey"), "{dir:?}");
                assert!(dir.is_dir());
            }
            Err(Error::VaultPathUnavailable) => {
                assert!(std::env::var_os("LOCALAPPDATA").is_none_or(|v| v.is_empty()));
            }
            Err(e) => return Err(e),
        }
        Ok(())
    }

    #[test]
    fn writing_replaces_the_file_and_leaves_no_temp_file() -> Result<()> {
        let dir = temp_dir("atomic")?;
        let path = dir.join("a.cfg");
        write_atomic(&path, b"one")?;
        write_atomic(&path, b"two")?;
        assert_eq!(fs::read(&path)?, b"two");
        assert_eq!(fs::read_dir(&dir)?.count(), 1, "no temp file stays behind");
        fs::remove_dir_all(&dir)?;
        Ok(())
    }

    #[test]
    fn a_failed_write_names_the_file_and_keeps_the_error_kind() -> Result<()> {
        let dir = temp_dir("failed")?;
        let path = dir.join("missing-folder").join("a.cfg");
        let result = write_atomic(&path, b"x");
        fs::remove_dir_all(&dir)?;
        let message = match result {
            Err(Error::Io(e)) if e.kind() == io::ErrorKind::NotFound => e.to_string(),
            other => panic!("expected a NotFound I/O error, got {other:?}"),
        };
        assert!(message.contains("cannot write"), "{message}");
        assert!(message.contains("a.cfg"), "{message}");
        Ok(())
    }

    #[test]
    fn a_missing_tool_is_a_tool_error() {
        assert!(matches!(
            system_command("piikey-no-such-tool.exe"),
            Err(Error::Tool(message)) if message.contains("piikey-no-such-tool.exe")
        ));
    }

    #[test]
    fn a_system_tool_runs_and_its_output_is_captured() -> Result<()> {
        let out = run_system_tool("cmd.exe", &["/C", "echo", "piikey"])?;
        assert!(out.status.success());
        assert!(String::from_utf8_lossy(&out.stdout).contains("piikey"));
        Ok(())
    }
}
