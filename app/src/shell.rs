//! The Explorer right-click verb "Scan for PII".
//!
//! Per-user registration under `HKCU\Software\Classes`, so it needs no administrator rights and
//! leaves other users alone. The verb runs `piikey.exe --scan <path>`, once for each item that is
//! selected. On Windows 11 the classic verbs sit under "Show more options"; the top-level menu
//! needs a signed package and a COM DLL.

use std::{
    ffi::OsString,
    io::ErrorKind,
    path::{Path, PathBuf},
};

use winreg::{RegKey, enums::HKEY_CURRENT_USER};

use crate::{Res, ui::SCAN_FLAG};

/// Where the verbs live, relative to the user's registry root.
const CLASSES: &str = r"Software\Classes";
/// The verb's key name under each `shell` key.
const VERB: &str = "piikey.scan";
/// The menu text.
const LABEL: &str = "Scan for PII";
/// What Explorer is told to open: files, folders, and the background of an open folder. The
/// background verb gets its folder as `%V\.`, not `%V`: the path of a drive's root, `C:\`, would
/// end the quoted argument in `\"`, which Windows reads as a quote and not as the end of the path.
/// [`scan_paths`] takes the `\.` off again.
const TARGETS: [(&str, &str); 3] = [
    (r"*\shell", "%1"),
    (r"Directory\shell", "%1"),
    (r"Directory\Background\shell", r"%V\."),
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

/// The paths that follow `--scan` on the command line the verb runs: what Explorer put in place
/// of `%1` and `%V`, made absolute.
pub fn scan_paths(args: impl Iterator<Item = OsString>) -> Vec<PathBuf> {
    args.map(|arg| std::path::absolute(&arg).unwrap_or_else(|_| PathBuf::from(arg)))
        .collect()
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
            command.set_value("", &format!("\"{exe}\" {SCAN_FLAG} \"{argument}\"")),
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

    use super::{SCAN_FLAG, TARGETS, register_in, scan_paths, unregister_in};
    use crate::{Describe, Res};

    const EXE: &str = r"C:\Apps\piikey\piikey.exe";

    /// A private registry tree, so a test never touches the user's real Explorer menu. It goes
    /// away with the test, whether the test passes or not.
    struct Sandbox {
        tree: String,
        classes: String,
    }

    impl Sandbox {
        fn new(tag: &str) -> Self {
            let tree = format!(r"Software\piikey-shell-test-{}-{tag}", std::process::id());
            Self {
                classes: format!(r"{tree}\Classes"),
                tree,
            }
        }

        /// The string value `name` of the key `path` below the sandbox's classes.
        fn value(&self, path: &str, name: &str) -> Res<String> {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey(format!(r"{}\{path}", self.classes))
                .and_then(|key| key.get_value::<String, _>(name))
                .map_err(|e| format!("{path} {name}: {e}"))
        }

        fn has(&self, path: &str) -> bool {
            RegKey::predef(HKEY_CURRENT_USER)
                .open_subkey(format!(r"{}\{path}", self.classes))
                .is_ok()
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.tree);
        }
    }

    /// The arguments Windows hands a program that was started with `line`, by the rules of
    /// `CommandLineToArgvW`: backslashes count only in front of a quote, where a pair stands for
    /// one backslash and an odd one before the quote makes it a letter.
    fn arguments(line: &str) -> Vec<String> {
        let (mut args, mut current) = (Vec::new(), String::new());
        let (mut quoted, mut started) = (false, false);
        let mut chars = line.chars().peekable();
        while let Some(c) = chars.next() {
            match c {
                '\\' => {
                    let mut slashes = 1;
                    while chars.next_if_eq(&'\\').is_some() {
                        slashes += 1;
                    }
                    if chars.next_if_eq(&'"').is_some() {
                        current.push_str(&"\\".repeat(slashes / 2));
                        if slashes % 2 == 1 {
                            current.push('"');
                        } else {
                            quoted = !quoted;
                        }
                    } else {
                        current.push_str(&"\\".repeat(slashes));
                    }
                    started = true;
                }
                '"' => {
                    quoted = !quoted;
                    started = true;
                }
                c if c.is_whitespace() && !quoted => {
                    if std::mem::take(&mut started) {
                        args.push(std::mem::take(&mut current));
                    }
                }
                c => {
                    current.push(c);
                    started = true;
                }
            }
        }
        if started {
            args.push(current);
        }
        args
    }

    #[test]
    fn register_writes_the_verbs_and_unregister_removes_only_them() -> Res<()> {
        let sandbox = Sandbox::new("roundtrip");
        let exe = Path::new(EXE);
        // A verb of another program on the same menu.
        let root = RegKey::predef(HKEY_CURRENT_USER);
        for (shell, _) in TARGETS {
            root.create_subkey(format!(r"{}\{shell}\other", sandbox.classes))
                .describe()?;
        }
        register_in(&sandbox.classes, exe)?;
        for (shell, _) in TARGETS {
            let verb = format!(r"{shell}\piikey.scan");
            assert!(
                !sandbox.value(&verb, "MUIVerb")?.is_empty(),
                "{shell} has a label"
            );
            assert!(
                sandbox
                    .value(&verb, "Icon")?
                    .starts_with(&format!("\"{EXE}\"")),
                "{shell} shows the icon of the app"
            );
            assert!(
                sandbox
                    .value(&format!(r"{verb}\command"), "")?
                    .starts_with(&format!("\"{EXE}\" {SCAN_FLAG} ")),
                "{shell} runs the scan"
            );
        }

        // Registering again points the verbs at the exe where it is now.
        register_in(&sandbox.classes, Path::new(r"D:\Moved\piikey.exe"))?;
        assert!(
            sandbox
                .value(r"*\shell\piikey.scan\command", "")?
                .starts_with(&format!(r#""D:\Moved\piikey.exe" {SCAN_FLAG} "#))
        );

        unregister_in(&sandbox.classes)?;
        unregister_in(&sandbox.classes)?;
        for (shell, _) in TARGETS {
            assert!(!sandbox.has(&format!(r"{shell}\piikey.scan")), "{shell}");
            assert!(sandbox.has(&format!(r"{shell}\other")), "{shell}: not ours");
        }
        Ok(())
    }

    #[test]
    fn every_verb_hands_over_the_path_it_was_asked_about() -> Res<()> {
        let sandbox = Sandbox::new("paths");
        register_in(&sandbox.classes, Path::new(EXE))?;
        for (shell, placeholder, path) in [
            (r"*\shell", "%1", r"C:\Users\jan jansen\Documents\a b.docx"),
            (r"Directory\shell", "%1", r"C:\Users\jan jansen\Documents"),
            (
                r"Directory\Background\shell",
                "%V",
                r"C:\Users\jan jansen\Documents",
            ),
            // The background of a drive's root and of a share's root end in a backslash.
            (r"Directory\Background\shell", "%V", r"D:\"),
            (r"Directory\Background\shell", "%V", r"\\server\share\"),
        ] {
            let command = sandbox.value(&format!(r"{shell}\piikey.scan\command"), "")?;
            let line = command.replace(placeholder, path);
            let args = arguments(&line);
            assert_eq!(args[..2], [EXE, SCAN_FLAG], "{shell}: {line}");
            let paths = scan_paths(args[2..].iter().map(Into::into));
            // Windows names a share's root with or without its last backslash.
            let named = |path: &Path| path.to_string_lossy().trim_end_matches('\\').to_owned();
            assert_eq!(paths.len(), 1, "{shell} {path}: {line}");
            assert_eq!(named(&paths[0]), named(Path::new(path)), "{shell}: {line}");
        }
        Ok(())
    }
}
