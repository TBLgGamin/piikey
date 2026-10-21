//! The Explorer right-click verb "Scan for PII".
//!
//! Per-user registration under `HKCU\Software\Classes`, so it needs no administrator rights and
//! leaves other users alone. The verb runs `piikey.exe --scan <paths>`. On Windows 11 the classic
//! verbs sit under "Show more options"; the top-level menu needs a signed package and a COM DLL.

use std::io::ErrorKind;
use std::path::Path;

use winreg::{RegKey, enums::HKEY_CURRENT_USER};

use crate::Res;

/// Where the verbs live, relative to the user's registry root.
const CLASSES: &str = r"Software\Classes";
/// The verb's key name under each `shell` key.
const VERB: &str = "piikey.scan";
/// The menu text.
const LABEL: &str = "Scan for PII";
/// What Explorer is told to open: files, folders, and the background of an open folder.
const TARGETS: [(&str, &str); 3] = [
    (r"*\shell", "%1"),
    (r"Directory\shell", "%1"),
    (r"Directory\Background\shell", "%V"),
];

/// Adds the verb for files, folders and folder backgrounds, pointing at `exe`. Safe to repeat: it
/// refreshes the path, which a moved portable install needs.
///
/// # Errors
/// A message when a registry key cannot be written.
pub fn register(exe: &Path) -> Res<()> {
    register_in(CLASSES, exe)
}

/// Removes the verb. A verb that is not there is fine.
///
/// # Errors
/// A message when a registry key cannot be removed.
pub fn unregister() -> Res<()> {
    unregister_in(CLASSES)
}

fn register_in(classes: &str, exe: &Path) -> Res<()> {
    let exe = exe.display();
    let root = RegKey::predef(HKEY_CURRENT_USER);
    for (shell, argument) in TARGETS {
        let verb = format!(r"{classes}\{shell}\{VERB}");
        let write = |what: &str, result: std::io::Result<()>| {
            result.map_err(|e| format!("could not write HKCU\\{verb} ({what}): {e}"))
        };
        let (key, _) = root
            .create_subkey(&verb)
            .map_err(|e| format!("could not create HKCU\\{verb}: {e}"))?;
        write("MUIVerb", key.set_value("MUIVerb", &LABEL))?;
        write("Icon", key.set_value("Icon", &format!("\"{exe}\",0")))?;
        write(
            "MultiSelectModel",
            key.set_value("MultiSelectModel", &"Player"),
        )?;
        let (command, _) = key
            .create_subkey("command")
            .map_err(|e| format!("could not create HKCU\\{verb}\\command: {e}"))?;
        write(
            "command",
            command.set_value("", &format!("\"{exe}\" --scan \"{argument}\"")),
        )?;
    }
    Ok(())
}

fn unregister_in(classes: &str) -> Res<()> {
    let root = RegKey::predef(HKEY_CURRENT_USER);
    for (shell, _) in TARGETS {
        let verb = format!(r"{classes}\{shell}\{VERB}");
        match root.delete_subkey_all(&verb) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(format!("could not remove HKCU\\{verb}: {e}")),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use winreg::{RegKey, enums::HKEY_CURRENT_USER};

    use super::{register_in, unregister_in};
    use crate::Res;

    /// A private tree, so the test never touches the user's real Explorer menu.
    fn sandbox() -> String {
        format!(r"Software\piikey-shell-test-{}\Classes", std::process::id())
    }

    #[test]
    fn register_writes_the_verbs_and_unregister_removes_them() -> Res<()> {
        let classes = sandbox();
        let exe = Path::new(r"C:\Apps\piikey\piikey.exe");
        register_in(&classes, exe)?;

        let root = RegKey::predef(HKEY_CURRENT_USER);
        let command = |shell: &str| -> Res<String> {
            root.open_subkey(format!(r"{classes}\{shell}\piikey.scan\command"))
                .and_then(|key| key.get_value::<String, _>(""))
                .map_err(|e| e.to_string())
        };
        assert_eq!(
            command(r"*\shell")?,
            r#""C:\Apps\piikey\piikey.exe" --scan "%1""#
        );
        assert_eq!(
            command(r"Directory\shell")?,
            r#""C:\Apps\piikey\piikey.exe" --scan "%1""#
        );
        assert_eq!(
            command(r"Directory\Background\shell")?,
            r#""C:\Apps\piikey\piikey.exe" --scan "%V""#
        );
        let verb = root
            .open_subkey(format!(r"{classes}\*\shell\piikey.scan"))
            .map_err(|e| e.to_string())?;
        let value = |name: &str| verb.get_value::<String, _>(name).map_err(|e| e.to_string());
        assert_eq!(value("MUIVerb")?, "Scan for PII");
        assert_eq!(value("MultiSelectModel")?, "Player");
        assert_eq!(value("Icon")?, r#""C:\Apps\piikey\piikey.exe",0"#);

        unregister_in(&classes)?;
        unregister_in(&classes)?;
        let gone = root
            .open_subkey(format!(r"{classes}\*\shell\piikey.scan"))
            .is_err();
        // The sandbox itself is ours to delete, even when the assertion below fails.
        let parent = classes.trim_end_matches(r"\Classes");
        root.delete_subkey_all(parent).map_err(|e| e.to_string())?;
        assert!(gone, "unregister left the verb behind");
        Ok(())
    }
}
