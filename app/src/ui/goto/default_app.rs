//! Which exe Windows opens a file with, read from the registry the way Explorer reads it.
//!
//! The file type is the extension. The user's choice (`HKEY_CURRENT_USER\Software\Microsoft\
//! Windows\CurrentVersion\Explorer\FileExts\.<ext>\UserChoice`, value `ProgId`) wins; without
//! one, the default value of `HKEY_CLASSES_ROOT\.<ext>` names the class. Its verb `open` has a
//! command line, `HKEY_CLASSES_ROOT\<class>\shell\open\command`, and the exe is what it starts.
//! A class without a command line (a packaged app, such as the new Notepad, is started by
//! Windows in another way) has no exe to name: that, and every failure, is "unknown".

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
};

use winreg::{
    RegKey,
    enums::{HKEY_CLASSES_ROOT, HKEY_CURRENT_USER},
};

/// Where the user's choices of app for file types are, under `HKEY_CURRENT_USER`.
const CHOICES: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts";

/// The exe that opens `file` by default, from the extension of its name; `None` when it has no
/// extension, Windows has no exe for it, or the registry cannot be read.
pub(super) fn default_exe(file: &Path) -> Option<PathBuf> {
    let extension = file.extension()?.to_str()?;
    let classes = RegKey::predef(HKEY_CLASSES_ROOT);
    let choices = RegKey::predef(HKEY_CURRENT_USER).open_subkey(CHOICES).ok();
    exe_in(&classes, choices.as_ref(), extension, environment)
}

/// The value of the environment variable `name`.
fn environment(name: &str) -> Option<OsString> {
    std::env::var_os(name)
}

/// [`default_exe`] over the keys that hold the classes and the user's choices, and with `var` to
/// say what an environment variable holds.
fn exe_in(
    classes: &RegKey,
    choices: Option<&RegKey>,
    extension: &str,
    var: impl Fn(&str) -> Option<OsString>,
) -> Option<PathBuf> {
    let class = class_of(classes, choices, extension)?;
    let command: String = classes
        .open_subkey(format!(r"{class}\shell\open\command"))
        .ok()?
        .get_value("")
        .ok()?;
    exe_of(&command, var)
}

/// The class that `extension` opens as: what the user chose, else what the extension names.
fn class_of(classes: &RegKey, choices: Option<&RegKey>, extension: &str) -> Option<String> {
    let chosen = choices
        .and_then(|choices| {
            choices
                .open_subkey(format!(r".{extension}\UserChoice"))
                .ok()
        })
        .and_then(|key| key.get_value::<String, _>("ProgId").ok())
        .filter(|class| !class.is_empty());
    chosen.or_else(|| {
        classes
            .open_subkey(format!(".{extension}"))
            .ok()?
            .get_value::<String, _>("")
            .ok()
            .filter(|class| !class.is_empty())
    })
}

/// The exe that the command line `command` starts, after the environment variables in it
/// (`%SystemRoot%`) are replaced with what `var` says they hold. It is quoted
/// (`"C:\Program Files\x\x.exe" "%1"`), or runs to the first white space after `.exe`
/// (`%SystemRoot%\system32\NOTEPAD.EXE %1`: the path may hold spaces when it is not quoted), or
/// is the first word when there is no `.exe` in it. `None` when there is nothing to start.
fn exe_of(command: &str, var: impl Fn(&str) -> Option<OsString>) -> Option<PathBuf> {
    let command = expand(command, var);
    let command = command.trim_start();
    let exe = match command.strip_prefix('"') {
        Some(quoted) => quoted.split('"').next().unwrap_or_default(),
        None => unquoted_exe(command),
    }
    .trim();
    (!exe.is_empty()).then(|| PathBuf::from(exe))
}

/// The start of `command`, which is not quoted, up to the end of the first `.exe` that is followed
/// by white space or ends it; the first word when there is none.
fn unquoted_exe(command: &str) -> &str {
    // Lowercasing ASCII keeps every byte position, so positions in the one are those of the other.
    let lower = command.to_ascii_lowercase();
    let end = lower
        .match_indices(".exe")
        .map(|(at, exe)| at + exe.len())
        .find(|&end| {
            command[end..]
                .chars()
                .next()
                .is_none_or(char::is_whitespace)
        });
    match end {
        Some(end) => &command[..end],
        None => command.split_whitespace().next().unwrap_or_default(),
    }
}

/// `text` with each `%NAME%` that `var` knows replaced by its value. What it does not know stays
/// as it is, as in Windows: `%1` is no variable.
fn expand(text: &str, var: impl Fn(&str) -> Option<OsString>) -> String {
    let mut expanded = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('%') {
        expanded.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let known = after.find('%').and_then(|close| {
            let name = &after[..close];
            if name.is_empty() {
                return None;
            }
            var(name).map(|value| (close, value))
        });
        if let Some((close, value)) = known {
            expanded.push_str(&value.to_string_lossy());
            rest = &after[close + 1..];
        } else {
            expanded.push('%');
            rest = after;
        }
    }
    expanded.push_str(rest);
    expanded
}

#[cfg(test)]
mod tests {
    use winreg::{RegValue, enums::REG_EXPAND_SZ};

    use super::*;
    use crate::{Describe, Res};

    /// What the tests say `%SystemRoot%` is.
    fn environment_of_the_test(name: &str) -> Option<OsString> {
        (name == "SystemRoot").then(|| OsString::from(r"C:\Windows"))
    }

    fn exe(command: &str) -> Option<String> {
        exe_of(command, environment_of_the_test).map(|exe| exe.to_string_lossy().into_owned())
    }

    #[test]
    fn a_quoted_exe_may_hold_spaces() {
        assert_eq!(
            exe(r#""C:\Program Files\Microsoft VS Code\Code.exe" "%1""#).as_deref(),
            Some(r"C:\Program Files\Microsoft VS Code\Code.exe")
        );
    }

    #[test]
    fn what_follows_a_quoted_exe_is_left_out() {
        assert_eq!(
            exe(r#""C:\Program Files\Notepad++\notepad++.exe" -multiInst -nosession "%1""#)
                .as_deref(),
            Some(r"C:\Program Files\Notepad++\notepad++.exe")
        );
        // The quote is never closed: the rest is the path.
        assert_eq!(exe(r#""C:\a b\x.exe"#).as_deref(), Some(r"C:\a b\x.exe"));
    }

    #[test]
    fn environment_variables_are_expanded_in_an_unquoted_command() {
        assert_eq!(
            exe(r"%SystemRoot%\system32\NOTEPAD.EXE %1").as_deref(),
            Some(r"C:\Windows\system32\NOTEPAD.EXE")
        );
        // Quoted, a variable is expanded just the same.
        assert_eq!(
            exe(r#""%SystemRoot%\notepad.exe" "%1""#).as_deref(),
            Some(r"C:\Windows\notepad.exe")
        );
    }

    #[test]
    fn an_unquoted_path_with_spaces_runs_to_the_end_of_the_exe() {
        assert_eq!(
            exe(r#"C:\Program Files\Sublime Text\sublime_text.exe "%1""#).as_deref(),
            Some(r"C:\Program Files\Sublime Text\sublime_text.exe")
        );
        assert_eq!(
            exe(r"C:\Tools\app.EXE --open %1").as_deref(),
            Some(r"C:\Tools\app.EXE")
        );
        // At the end of the command too.
        assert_eq!(
            exe(r"C:\Tools\app.exe").as_deref(),
            Some(r"C:\Tools\app.exe")
        );
        // `.exe` inside a name is not the end of it.
        assert_eq!(
            exe(r"C:\Tools\app.exe.d\run.exe %1").as_deref(),
            Some(r"C:\Tools\app.exe.d\run.exe")
        );
    }

    #[test]
    fn without_an_exe_in_the_command_the_first_word_is_it() {
        assert_eq!(exe(r#"cmd /c start "" "%1""#).as_deref(), Some("cmd"));
        assert_eq!(
            exe(r#""C:\Scripts\run it.bat" "%1""#).as_deref(),
            Some(r"C:\Scripts\run it.bat")
        );
    }

    #[test]
    fn nothing_to_start_is_no_exe() {
        for command in ["", "   ", r#""""#, r#""  ""#] {
            assert_eq!(exe(command), None, "{command:?}");
        }
    }

    #[test]
    fn a_variable_that_is_not_known_stays_as_it_is() {
        assert_eq!(
            exe(r"%NoSuchThing%\a.exe %1").as_deref(),
            Some(r"%NoSuchThing%\a.exe")
        );
        assert_eq!(
            expand("50% of %1 and 100%", environment_of_the_test),
            "50% of %1 and 100%"
        );
        assert_eq!(
            expand("%SystemRoot%\\x;%SystemRoot%", environment_of_the_test),
            r"C:\Windows\x;C:\Windows"
        );
        assert_eq!(expand("%%", environment_of_the_test), "%%");
    }

    /// A private registry tree that stands for the classes and the user's choices, so a test never
    /// reads or changes the file types of the user. It goes away with the test, whether the test
    /// passes or not.
    struct Sandbox(String);

    impl Sandbox {
        fn new(tag: &str) -> Self {
            Self(format!(
                r"Software\piikey-goto-test-{}-{tag}",
                std::process::id()
            ))
        }

        /// The key `path` below the sandbox, made when it is not there.
        fn key(&self, path: &str) -> Res<RegKey> {
            let (key, _) = RegKey::predef(HKEY_CURRENT_USER)
                .create_subkey(format!(r"{}\{path}", self.0))
                .describe()?;
            Ok(key)
        }

        /// Sets the value `name` of the key `path` to `text`.
        fn set(&self, path: &str, name: &str, text: &str) -> Res<()> {
            self.key(path)?.set_value(name, &text).describe()
        }

        /// Sets the default value of the key `path` to `text`, as a value that Windows expands.
        fn set_expanding(&self, path: &str, text: &str) -> Res<()> {
            let bytes: Vec<u8> = text
                .encode_utf16()
                .chain(std::iter::once(0))
                .flat_map(u16::to_le_bytes)
                .collect();
            self.key(path)?
                .set_raw_value(
                    "",
                    &RegValue {
                        bytes: bytes.into(),
                        vtype: REG_EXPAND_SZ,
                    },
                )
                .describe()
        }
    }

    impl Drop for Sandbox {
        fn drop(&mut self) {
            let _ = RegKey::predef(HKEY_CURRENT_USER).delete_subkey_all(&self.0);
        }
    }

    #[test]
    fn the_exe_comes_from_the_class_of_the_extension_or_the_choice_of_the_user() -> Res<()> {
        let sandbox = Sandbox::new("classes");
        // `.txt` names a class whose command is stored for Windows to expand.
        sandbox.set(r"Classes\.txt", "", "txtfile")?;
        sandbox.set_expanding(
            r"Classes\txtfile\shell\open\command",
            r"%SystemRoot%\system32\NOTEPAD.EXE %1",
        )?;
        // `.md` names a class too, but the user chose an app for it: the choice wins.
        sandbox.set(r"Classes\.md", "", "markdown.file")?;
        sandbox.set(
            r"Classes\markdown.file\shell\open\command",
            "",
            r#""C:\Windows\system32\other.exe" "%1""#,
        )?;
        sandbox.set(
            r"FileExts\.md\UserChoice",
            "ProgId",
            r"Applications\Code.exe",
        )?;
        sandbox.set(
            r"Classes\Applications\Code.exe\shell\open\command",
            "",
            r#""C:\Users\Jan Jansen\AppData\Local\Programs\Microsoft VS Code\Code.exe" "%1""#,
        )?;
        // A packaged app: the class has no command line to read an exe from.
        sandbox.set(r"Classes\.pkg", "", "AppX0123456789")?;
        sandbox.key(r"Classes\AppX0123456789\Application")?;
        // A choice that names nothing, and a class that is not there.
        sandbox.set(r"FileExts\.nothing\UserChoice", "ProgId", "")?;
        sandbox.set(r"Classes\.ghost", "", "NotAClass")?;

        let (classes, choices) = (sandbox.key("Classes")?, sandbox.key("FileExts")?);
        let found = |extension: &str| {
            exe_in(&classes, Some(&choices), extension, environment_of_the_test)
                .map(|exe| exe.to_string_lossy().into_owned())
        };
        assert_eq!(
            found("txt").as_deref(),
            Some(r"C:\Windows\system32\NOTEPAD.EXE")
        );
        // Registry keys do not mind the letter case.
        assert_eq!(found("TXT"), found("txt"));
        assert_eq!(
            found("md").as_deref(),
            Some(r"C:\Users\Jan Jansen\AppData\Local\Programs\Microsoft VS Code\Code.exe")
        );
        assert_eq!(found("pkg"), None);
        assert_eq!(found("nothing"), None);
        assert_eq!(found("ghost"), None);
        assert_eq!(found("unknown"), None);
        // Without the user's choices, the class of the extension is the only way.
        assert_eq!(
            exe_in(&classes, None, "md", environment_of_the_test)
                .map(|exe| exe.to_string_lossy().into_owned())
                .as_deref(),
            Some(r"C:\Windows\system32\other.exe")
        );
        Ok(())
    }

    #[test]
    fn a_file_without_an_extension_has_no_exe() {
        assert_eq!(default_exe(Path::new(r"C:\Users\Jan\Makefile")), None);
        assert_eq!(default_exe(Path::new("")), None);
    }
}
