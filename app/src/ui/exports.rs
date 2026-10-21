//! Files the app writes for the user: the vault and the inventory's report as CSV in Downloads, and
//! the masked copy of a file beside it. Nothing here overwrites a file.

use std::{
    fs::{self, File, OpenOptions},
    path::{Path, PathBuf},
};

use piikey::{
    detect::Mode,
    engine::Engine,
    files,
    formats::{self, Output},
    inventory::Inventory,
    vault::{self, ExportFormat},
};
use windows_reactor::DateTime;

use crate::Res;

/// `%USERPROFILE%\Downloads`.
///
/// # Errors
/// `USERPROFILE` is not set.
pub fn downloads() -> Res<PathBuf> {
    let home = std::env::var_os("USERPROFILE")
        .ok_or("USERPROFILE is not set, so there is no Downloads folder")?;
    Ok(PathBuf::from(home).join("Downloads"))
}

/// The local time as `YYYYMMDD-HHMMSS`: it makes the names of the files written here.
pub fn stamp() -> String {
    let now = DateTime::now().to_local();
    format!(
        "{:04}{:02}{:02}-{:02}{:02}{:02}",
        now.year(),
        now.month(),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

/// Writes a new file `name` in `dir`, made when missing, with what `write` puts in it; a file that
/// was not written whole is removed again, so no half of the vault is left behind.
fn write_new(dir: &Path, name: &str, write: impl FnOnce(&mut File) -> Res<()>) -> Res<PathBuf> {
    fs::create_dir_all(dir).map_err(|e| format!("could not create {}: {e}", dir.display()))?;
    let path = dir.join(name);
    // `create_new`: an existing file is somebody's, and is never replaced.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|e| format!("could not create {}: {e}", path.display()))?;
    let written = write(&mut file).and_then(|()| {
        file.sync_all()
            .map_err(|e| format!("could not write {}: {e}", path.display()))
    });
    match written {
        Ok(()) => Ok(path),
        Err(error) => {
            drop(file);
            // Nothing more to do when even that fails.
            let _ = fs::remove_file(&path);
            Err(error)
        }
    }
}

/// Writes every record of the vault as CSV to `piikey-vault-<stamp>.csv` in `dir`.
///
/// # Errors
/// A message when the file exists, or cannot be written, or the vault cannot be read.
pub fn vault_csv(engine: &Engine, dir: &Path, stamp: &str) -> Res<PathBuf> {
    write_new(dir, &format!("piikey-vault-{stamp}.csv"), |file| {
        let view = engine.vault().read().map_err(|e| e.to_string())?;
        vault::export(&view, ExportFormat::Csv, file)
            .map(drop)
            .map_err(|e| e.to_string())
    })
}

/// Writes the inventory's findings under `under` (everything when it is empty) as CSV to
/// `piikey-report-<stamp>.csv` in `dir`.
///
/// # Errors
/// A message when the file exists or cannot be written.
pub fn report_csv(inventory: &Inventory, under: &Path, dir: &Path, stamp: &str) -> Res<PathBuf> {
    write_new(dir, &format!("piikey-report-{stamp}.csv"), |file| {
        let under = (!under.as_os_str().is_empty()).then_some(under);
        inventory
            .report(under, ExportFormat::Csv, file)
            .map(drop)
            .map_err(|e| e.to_string())
    })
}

/// Writes the masked copy of `file` beside it (`name.masked.ext`, or `name.masked.txt` for a result
/// that is text) and returns where it is.
///
/// # Errors
/// A message when the file cannot be read or is not a format piikey reads, or the copy cannot be
/// written.
pub fn masked_copy(engine: &Engine, file: &Path) -> Res<PathBuf> {
    let bytes = fs::read(file).map_err(|e| format!("could not read {}: {e}", file.display()))?;
    let output = formats::process(engine, Mode::Anonymize, &bytes, 0)
        .map_err(|e| format!("could not mask {}: {e}", file.display()))?;
    let copy = files::masked_copy_path(file, &output);
    let data = match &output {
        Output::Same(bytes) => bytes.as_slice(),
        Output::Text(text) => text.as_bytes(),
    };
    fs::write(&copy, data).map_err(|e| format!("could not write {}: {e}", copy.display()))?;
    Ok(copy)
}

#[cfg(test)]
mod tests {
    use piikey::detect::EntityKind;
    use piikey::inventory::{Entry, Status};

    use super::*;
    use crate::ui::testing::TempDir;

    type Test = Result<(), String>;

    fn engine(dir: &TempDir) -> Result<Engine, String> {
        Engine::open(&dir.0.join("vault.pkv")).map_err(|e| e.to_string())
    }

    #[test]
    fn the_vault_is_written_as_csv_and_never_overwritten() -> Test {
        let dir = TempDir::new()?;
        let engine = engine(&dir)?;
        engine
            .run(Mode::Anonymize, &["mail jan.jansen@acme.nl"])
            .map_err(|e| e.to_string())?;
        let out = dir.0.join("out");
        let path = vault_csv(&engine, &out, "20260101-120000")?;
        assert_eq!(path, out.join("piikey-vault-20260101-120000.csv"));
        let text = fs::read_to_string(&path).map_err(|e| e.to_string())?;
        assert!(text.starts_with("kind,original,proxy"), "{text}");
        assert!(text.contains("jan.jansen@acme.nl"), "{text}");
        let again = vault_csv(&engine, &out, "20260101-120000");
        assert!(again.is_err(), "an existing file is never replaced");
        assert_eq!(
            fs::read_to_string(&path).map_err(|e| e.to_string())?,
            text,
            "and it is left as it was"
        );
        Ok(())
    }

    #[test]
    fn the_report_lists_what_the_inventory_found_under_a_folder() -> Test {
        let dir = TempDir::new()?;
        let inventory =
            Inventory::open(&dir.0.join("inventory.jsonl")).map_err(|e| e.to_string())?;
        let entry = |path: &str, hits| Entry {
            path: PathBuf::from(path),
            size: 10,
            modified: 1,
            scanned: 1_700_000_000,
            status: Status::Ok,
            counts: vec![(EntityKind::Iban, hits)],
        };
        inventory
            .record(vec![
                entry(r"C:\data\a.txt", 2),
                entry(r"D:\other\b.txt", 1),
            ])
            .map_err(|e| e.to_string())?;
        let out = dir.0.join("out");
        let all = report_csv(&inventory, Path::new(""), &out, "1")?;
        let text = fs::read_to_string(&all).map_err(|e| e.to_string())?;
        assert!(text.contains("a.txt") && text.contains("b.txt"), "{text}");
        assert!(
            text.lines().next().is_some_and(|h| h.contains("iban")),
            "{text}"
        );
        let some = report_csv(&inventory, Path::new(r"C:\data"), &out, "2")?;
        let text = fs::read_to_string(&some).map_err(|e| e.to_string())?;
        assert!(text.contains("a.txt") && !text.contains("b.txt"), "{text}");
        Ok(())
    }

    #[test]
    fn a_masked_copy_goes_beside_the_file_and_holds_no_original() -> Test {
        let dir = TempDir::new()?;
        let engine = engine(&dir)?;
        let file = dir.0.join("letter.txt");
        fs::write(&file, "mail jan.jansen@acme.nl please").map_err(|e| e.to_string())?;
        let copy = masked_copy(&engine, &file)?;
        assert_eq!(copy, dir.0.join("letter.masked.txt"));
        let text = fs::read_to_string(&copy).map_err(|e| e.to_string())?;
        assert!(
            text.starts_with("mail ") && text.ends_with(" please"),
            "{text}"
        );
        assert!(!text.contains("jan.jansen@acme.nl"), "{text}");
        assert_eq!(
            fs::read_to_string(&file).map_err(|e| e.to_string())?,
            "mail jan.jansen@acme.nl please",
            "the original is untouched"
        );
        Ok(())
    }

    #[test]
    fn a_file_piikey_cannot_read_is_an_error_with_its_name() -> Test {
        let dir = TempDir::new()?;
        let engine = engine(&dir)?;
        let missing = dir.0.join("missing.txt");
        let error = masked_copy(&engine, &missing)
            .err()
            .ok_or("a missing file cannot be masked")?;
        assert!(error.contains("missing.txt"), "{error}");
        Ok(())
    }

    #[test]
    fn file_names_carry_the_local_time() {
        let stamp = stamp();
        let (day, time) = stamp.split_once('-').unwrap_or_default();
        assert_eq!((day.len(), time.len()), (8, 6), "{stamp}");
        assert!(
            stamp.chars().all(|c| c.is_ascii_digit() || c == '-'),
            "{stamp}"
        );
    }
}
