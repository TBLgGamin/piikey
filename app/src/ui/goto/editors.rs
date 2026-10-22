//! The editors that open a file at a line and column when they are started with them, and the
//! arguments that say where.
//!
//! An editor is known by the name of its exe, as the registry names it for the file type: the
//! name is all that is compared, never a part of it (`notepad.exe` is no `notepad++.exe`).

use std::{ffi::OsString, path::Path};

/// An editor that takes a position on its command line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Editor {
    /// VS Code and VS Code Insiders: `Code.exe --goto <file>:<line>:<column>`.
    VsCode,
    /// `notepad++.exe -n<line> -c<column> <file>`.
    NotepadPlusPlus,
    /// `sublime_text.exe <file>:<line>:<column>`.
    SublimeText,
}

impl Editor {
    /// The editor that `exe` is, by its file name in any letter case; `None` for any other exe.
    pub(super) fn of(exe: &Path) -> Option<Self> {
        let name = exe.file_name()?.to_str()?.to_ascii_lowercase();
        match name.as_str() {
            "code.exe" | "code - insiders.exe" => Some(Self::VsCode),
            "notepad++.exe" => Some(Self::NotepadPlusPlus),
            "sublime_text.exe" => Some(Self::SublimeText),
            _ => None,
        }
    }

    /// The arguments that start the editor with `file` open at `line` and `column`, both counted
    /// from 1 (a 0 is read as 1). The file is one argument whatever its name holds: the command
    /// line is made from them with quotes where they are needed.
    pub(super) fn arguments(self, file: &Path, line: u32, column: u32) -> Vec<OsString> {
        let (line, column) = (line.max(1), column.max(1));
        match self {
            Self::VsCode => vec![OsString::from("--goto"), place(file, line, column)],
            Self::NotepadPlusPlus => vec![
                OsString::from(format!("-n{line}")),
                OsString::from(format!("-c{column}")),
                file.as_os_str().to_owned(),
            ],
            Self::SublimeText => vec![place(file, line, column)],
        }
    }
}

/// `<file>:<line>:<column>`: how VS Code and Sublime Text name a place in a file.
fn place(file: &Path, line: u32, column: u32) -> OsString {
    let mut argument = file.as_os_str().to_owned();
    argument.push(format!(":{line}:{column}"));
    argument
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = r"C:\Users\Jan Jansen\notes 2024.txt";

    fn args(editor: Editor, line: u32, column: u32) -> Vec<String> {
        editor
            .arguments(Path::new(FILE), line, column)
            .iter()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn vs_code_gets_goto_and_the_place_as_one_argument() {
        assert_eq!(
            args(Editor::VsCode, 12, 7),
            ["--goto", r"C:\Users\Jan Jansen\notes 2024.txt:12:7"]
        );
    }

    #[test]
    fn notepad_plus_plus_gets_the_line_and_the_column_and_then_the_path_on_its_own() {
        assert_eq!(args(Editor::NotepadPlusPlus, 12, 7), ["-n12", "-c7", FILE]);
    }

    #[test]
    fn sublime_text_gets_the_place_as_one_argument() {
        assert_eq!(
            args(Editor::SublimeText, 1, 1),
            [r"C:\Users\Jan Jansen\notes 2024.txt:1:1"]
        );
    }

    #[test]
    fn a_line_or_column_of_zero_is_the_first() {
        assert_eq!(
            args(Editor::SublimeText, 0, 0),
            [r"C:\Users\Jan Jansen\notes 2024.txt:1:1"]
        );
        assert_eq!(args(Editor::NotepadPlusPlus, 0, 5), ["-n1", "-c5", FILE]);
    }

    #[test]
    fn a_path_with_spaces_stays_one_argument() {
        for editor in [Editor::VsCode, Editor::NotepadPlusPlus, Editor::SublimeText] {
            let arguments = editor.arguments(Path::new(FILE), 3, 4);
            let holding_the_path = arguments
                .iter()
                .filter(|argument| argument.to_string_lossy().contains(FILE))
                .count();
            assert_eq!(holding_the_path, 1, "{editor:?}");
        }
    }

    #[test]
    fn editors_are_known_by_the_name_of_their_exe_in_any_letter_case() {
        for (exe, editor) in [
            (
                r"C:\Users\x\AppData\Local\Programs\Microsoft VS Code\Code.exe",
                Editor::VsCode,
            ),
            (r"C:\x\CODE.EXE", Editor::VsCode),
            (
                r"C:\Program Files\Microsoft VS Code Insiders\Code - Insiders.exe",
                Editor::VsCode,
            ),
            (
                r"C:\Program Files\Notepad++\notepad++.exe",
                Editor::NotepadPlusPlus,
            ),
            (r"C:\x\NOTEPAD++.EXE", Editor::NotepadPlusPlus),
            (
                r"C:\Program Files\Sublime Text\sublime_text.exe",
                Editor::SublimeText,
            ),
            (r"C:\x\Sublime_Text.exe", Editor::SublimeText),
        ] {
            assert_eq!(Editor::of(Path::new(exe)), Some(editor), "{exe}");
        }
    }

    #[test]
    fn a_part_of_the_name_does_not_make_an_editor() {
        for exe in [
            r"C:\Windows\system32\NOTEPAD.EXE",
            r"C:\Windows\notepad.exe",
            r"C:\x\mycode.exe",
            r"C:\x\code.exe.bak",
            r"C:\x\code-insiders.exe",
            r"C:\x\subl.exe",
            r"C:\Program Files\Notepad++\updater\GUP.exe",
            r"C:\Program Files\Microsoft VS Code\Code.exe\x.txt",
            "Code",
            "",
        ] {
            assert_eq!(Editor::of(Path::new(exe)), None, "{exe}");
        }
    }
}
