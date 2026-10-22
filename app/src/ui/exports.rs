//! Files the app writes for the user: the vault and the inventory's report as CSV in Downloads, and
//! the masked copy of a file beside it. Nothing here overwrites a file.

use std::{
    fs,
    io::{self, BufWriter, Write},
    path::{Path, PathBuf},
};

use piikey::{
    detect::Mode,
    engine::Engine,
    files,
    formats::{self, Output},
    inventory::Inventory,
    sys::write_new,
    vault::{self, ExportFormat},
};
use windows_reactor::DateTime;

use crate::{Describe, Res};

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

/// Writes every record of the vault as CSV to `piikey-vault-<stamp>.csv` in `dir`, made when
/// missing.
///
/// # Errors
/// A message when the file exists, or cannot be written, or the vault cannot be read.
pub fn vault_csv(engine: &Engine, dir: &Path, stamp: &str) -> Res<PathBuf> {
    let path = dir.join(format!("piikey-vault-{stamp}.csv"));
    write_new(&path, |file| {
        let view = engine.vault().read()?;
        vault::export(&view, ExportFormat::Csv, file)
    })
    .map(|_| path)
    .describe()
}

/// Writes the inventory's findings under `under` (everything when it is empty) as CSV to
/// `piikey-report-<stamp>.csv` in `dir`, made when missing.
///
/// # Errors
/// A message when the file exists or cannot be written.
pub fn report_csv(inventory: &Inventory, under: &Path, dir: &Path, stamp: &str) -> Res<PathBuf> {
    let path = dir.join(format!("piikey-report-{stamp}.csv"));
    let under = (!under.as_os_str().is_empty()).then_some(under);
    write_new(&path, |file| {
        // The report writes field by field: through a buffer, not one system call for each.
        inventory.report(under, ExportFormat::Csv, &mut BufWriter::new(file))
    })
    .map(|_| path)
    .describe()
}

/// Writes the masked copy of `file` beside it (`name.masked.ext`, or `name.masked.txt` for a result
/// that is text) and returns where it is. A file that has that name already is somebody's and
/// stays as it is.
///
/// # Errors
/// A message when the file cannot be read or is not a format piikey reads, or the copy exists or
/// cannot be written.
pub fn masked_copy(engine: &Engine, file: &Path) -> Res<PathBuf> {
    let bytes = fs::read(file).map_err(|e| format!("could not read {}: {e}", file.display()))?;
    let output = formats::process(engine, Mode::Anonymize, &bytes, 0)
        .map_err(|e| format!("could not mask {}: {e}", file.display()))?;
    let copy = files::masked_copy_path(file, &output);
    let data = match &output {
        Output::Same(bytes) => bytes.as_slice(),
        Output::Text(text) => text.as_bytes(),
    };
    write_new(&copy, |out| {
        out.write_all(data).map_err(|e| {
            io::Error::new(e.kind(), format!("cannot write {}: {e}", copy.display())).into()
        })
    })
    .map(|()| copy)
    .describe()
}

#[cfg(test)]
mod tests {
    use piikey::detect::EntityKind;
    use piikey::inventory::{Entry, Status};

    use super::*;
    use crate::ui::testing::TempDir;

    type Test = Result<(), String>;

    fn engine(dir: &TempDir) -> Result<Engine, String> {
        Engine::open(&dir.0.join("vault.pkv")).describe()
    }

    #[test]
    fn the_vault_is_written_as_csv_and_never_overwritten() -> Test {
        let dir = TempDir::new()?;
        let engine = engine(&dir)?;
        engine
            .run(Mode::Anonymize, &["mail jan.jansen@acme.nl"])
            .describe()?;
        let out = dir.0.join("out");
        let path = vault_csv(&engine, &out, "20260101-120000")?;
        assert_eq!(path, out.join("piikey-vault-20260101-120000.csv"));
        let text = fs::read_to_string(&path).describe()?;
        assert!(text.starts_with("kind,original,proxy"), "{text}");
        assert!(text.contains("jan.jansen@acme.nl"), "{text}");
        let again = vault_csv(&engine, &out, "20260101-120000");
        assert!(again.is_err(), "an existing file is never replaced");
        assert_eq!(
            fs::read_to_string(&path).describe()?,
            text,
            "and it is left as it was"
        );
        Ok(())
    }

    #[test]
    fn the_report_lists_what_the_inventory_found_under_a_folder() -> Test {
        let dir = TempDir::new()?;
        let inventory = Inventory::open(&dir.0.join("inventory.jsonl")).describe()?;
        let entry = |path: &str, hits| Entry {
            path: PathBuf::from(path),
            size: 10,
            modified: 1,
            scanned: 1_700_000_000,
            status: Status::Ok,
            counts: vec![(EntityKind::Iban, hits)],
            hash: None,
        };
        inventory
            .record(vec![
                entry(r"C:\data\a.txt", 2),
                entry(r"D:\other\b.txt", 1),
            ])
            .describe()?;
        let out = dir.0.join("out");
        let all = report_csv(&inventory, Path::new(""), &out, "1")?;
        let text = fs::read_to_string(&all).describe()?;
        assert!(text.contains("a.txt") && text.contains("b.txt"), "{text}");
        assert!(
            text.lines().next().is_some_and(|h| h.contains("iban")),
            "{text}"
        );
        let some = report_csv(&inventory, Path::new(r"C:\data"), &out, "2")?;
        let text = fs::read_to_string(&some).describe()?;
        assert!(text.contains("a.txt") && !text.contains("b.txt"), "{text}");
        Ok(())
    }

    #[test]
    fn a_masked_copy_goes_beside_the_file_and_holds_no_original() -> Test {
        let dir = TempDir::new()?;
        let engine = engine(&dir)?;
        let file = dir.0.join("letter.txt");
        fs::write(&file, "mail jan.jansen@acme.nl please").describe()?;
        let copy = masked_copy(&engine, &file)?;
        assert_eq!(copy, dir.0.join("letter.masked.txt"));
        let text = fs::read_to_string(&copy).describe()?;
        assert!(
            text.starts_with("mail ") && text.ends_with(" please"),
            "{text}"
        );
        assert!(!text.contains("jan.jansen@acme.nl"), "{text}");
        assert_eq!(
            fs::read_to_string(&file).describe()?,
            "mail jan.jansen@acme.nl please",
            "the original is untouched"
        );
        Ok(())
    }

    #[test]
    fn a_masked_copy_never_replaces_a_file() -> Test {
        let dir = TempDir::new()?;
        let engine = engine(&dir)?;
        let file = dir.0.join("letter.txt");
        fs::write(&file, "mail jan.jansen@acme.nl please").describe()?;
        // Somebody's file, or the copy made before, has the name the copy would get.
        let taken = dir.0.join("letter.masked.txt");
        fs::write(&taken, "not for piikey to touch").describe()?;
        let error = masked_copy(&engine, &file)
            .err()
            .ok_or("a copy must not replace a file")?;
        assert!(error.contains("letter.masked.txt"), "{error}");
        assert_eq!(
            fs::read_to_string(&taken).describe()?,
            "not for piikey to touch"
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
