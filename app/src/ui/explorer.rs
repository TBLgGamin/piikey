//! Opens files and folders in Windows Explorer: the Inventory treemap's "Open" and "Show in Explorer",
//! the file an export or a masked copy has just written. A web address (a cloud file's page, a
//! sign-in) goes to the default browser through Windows' `Launcher`, never through Explorer: Explorer
//! reads its argument as a path and cuts it at 259 characters, which dropped the `state` of a sign-in.
//!
//! Explorer is started from its full path under `SystemRoot`, never as a bare `explorer.exe` that
//! the search path could answer with something else, and its window stays visible, which is why
//! `piikey::sys::system_command` (it hides the window) is not used. The path goes onto the command
//! line as it is, between quotes: std would quote `/select,C:\a b` as one `"/select,C:\a b"`
//! argument, and Explorer reads that as a folder name.

use std::{
    ffi::{OsStr, OsString},
    os::windows::process::CommandExt,
    path::{Path, PathBuf},
    process::Command,
    thread,
};

use windows::{Foundation::Uri, System::Launcher, core::HSTRING};

use crate::{Describe, Res};

/// The longest web address that is opened; no page piikey opens has an address near it.
const MOST_URL: usize = 8_000;

/// Opens the folder that holds `path` with `path` selected: `explorer.exe /select,"<path>"`.
///
/// # Errors
/// Windows does not say where it is installed, or Explorer cannot be started.
pub fn show(path: &Path) -> Res<()> {
    start(select_argument(path))
}

/// Opens `path`: a folder in Explorer, a file in the program Windows opens it with:
/// `explorer.exe "<path>"`.
///
/// # Errors
/// Windows does not say where it is installed, or Explorer cannot be started.
pub fn open(path: &Path) -> Res<()> {
    start(quoted(path))
}

/// Opens the web address `url` in the user's default browser. Only `http` and `https` addresses
/// are opened: Windows would start whatever else the text names (a file, an app that has a
/// protocol of its own). The launch runs on a thread of its own, so the window's thread never
/// waits on it.
///
/// # Errors
/// `url` is not a web address, or Windows did not open it.
pub fn open_url(url: &str) -> Res<()> {
    let url = HSTRING::from(web_url(url)?);
    let launched = thread::Builder::new()
        .name("piikey-open-url".to_owned())
        .spawn(move || -> Res<bool> {
            let uri = Uri::CreateUri(&url).describe()?;
            Launcher::LaunchUriAsync(&uri).describe()?.join().describe()
        })
        .describe()?
        .join()
        .map_err(|_| "Opening the browser stopped unexpectedly.".to_owned())??;
    if launched {
        Ok(())
    } else {
        Err("Windows did not open the browser.".to_owned())
    }
}

/// `url` when it is a web address with nothing in it a browser would read otherwise.
fn web_url(url: &str) -> Res<&str> {
    let lower = url.to_ascii_lowercase();
    let web = lower.starts_with("https://") || lower.starts_with("http://");
    let clean = !url
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '"');
    if !web || !clean || url.len() > MOST_URL {
        return Err("piikey only opens web addresses (https) in the browser.".to_owned());
    }
    Ok(url)
}

/// Runs Explorer with `argument` as its whole command line after the program name, and leaves it
/// running: the child is not waited for.
fn start(argument: OsString) -> Res<()> {
    let exe = explorer_exe(std::env::var_os("SystemRoot").as_deref())
        .ok_or("Windows did not say where it is installed (SystemRoot is not set).")?;
    Command::new(exe)
        .raw_arg(argument)
        .spawn()
        .map_err(|e| format!("Could not start Explorer: {e}"))?;
    Ok(())
}

/// `<SystemRoot>\explorer.exe`; `None` without a `SystemRoot`.
fn explorer_exe(system_root: Option<&OsStr>) -> Option<PathBuf> {
    system_root
        .filter(|root| !root.is_empty())
        .map(|root| Path::new(root).join("explorer.exe"))
}

/// `/select,"<path>"`.
fn select_argument(path: &Path) -> OsString {
    let mut argument = OsString::from("/select,");
    argument.push(quoted(path));
    argument
}

/// `path` between quotes, for the command line.
///
/// A backslash right before the closing quote reads as an escaped quote, so the path is rebuilt
/// from its components, which drops a trailing backslash. A drive root (`C:\`) has to keep its
/// backslash; a drive letter never holds a space, so it goes without quotes.
fn quoted(path: &Path) -> OsString {
    let clean: PathBuf = path.components().collect();
    let mut text = OsString::new();
    if clean.file_name().is_some() {
        text.push("\"");
        text.push(&clean);
        text.push("\"");
    } else {
        text.push(&clean);
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(argument: &OsStr) -> String {
        argument.to_string_lossy().into_owned()
    }

    #[test]
    fn show_selects_the_path_in_one_quoted_argument() {
        let argument = select_argument(Path::new(r"C:\Users\Jan Jansen\notes, 2024.txt"));
        assert_eq!(
            text(&argument),
            r#"/select,"C:\Users\Jan Jansen\notes, 2024.txt""#
        );
    }

    #[test]
    fn open_puts_the_path_in_quotes() {
        assert_eq!(
            text(&quoted(Path::new(r"C:\Users\Jan Jansen\Documents"))),
            r#""C:\Users\Jan Jansen\Documents""#
        );
    }

    #[test]
    fn a_trailing_backslash_does_not_swallow_the_closing_quote() {
        assert_eq!(
            text(&quoted(Path::new(r"C:\Users\me\"))),
            r#""C:\Users\me""#
        );
        assert_eq!(
            text(&select_argument(Path::new(r"D:\Data Files\"))),
            r#"/select,"D:\Data Files""#
        );
    }

    #[test]
    fn a_drive_root_keeps_its_backslash() {
        assert_eq!(text(&quoted(Path::new(r"C:\"))), r"C:\");
        assert_eq!(text(&select_argument(Path::new(r"C:\"))), r"/select,C:\");
    }

    #[test]
    fn explorer_comes_from_the_windows_folder() {
        assert_eq!(
            explorer_exe(Some(OsStr::new(r"C:\Windows"))),
            Some(PathBuf::from(r"C:\Windows\explorer.exe"))
        );
        assert_eq!(explorer_exe(Some(OsStr::new(""))), None);
        assert_eq!(explorer_exe(None), None);
    }

    #[test]
    fn a_web_address_is_opened_as_it_is() {
        let url = "https://contoso.sharepoint.com/sites/a?id=1&b=2";
        assert_eq!(web_url(url), Ok(url));
        assert!(web_url("HTTP://127.0.0.1:8080/x").is_ok());
        // A sign-in address is longer than Explorer's 259 characters.
        let sign_in = format!(
            "https://accounts.google.com/o/oauth2/v2/auth?{}",
            "a=b&".repeat(100)
        );
        assert_eq!(web_url(&sign_in), Ok(sign_in.as_str()));
    }

    #[test]
    fn only_web_addresses_are_opened() {
        for url in [
            "file:///C:/Windows/System32/calc.exe",
            r"C:\Windows\notepad.exe",
            "ms-settings:privacy",
            "javascript:alert(1)",
            "https://a.example/x\" /s",
            "https://a.example/a b",
            "https://a.example/a\nb",
            "",
        ] {
            assert!(web_url(url).is_err(), "{url:?}");
        }
        let long = format!("https://a.example/{}", "x".repeat(MOST_URL));
        assert!(web_url(&long).is_err());
    }
}
