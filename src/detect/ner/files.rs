//! The model's files: where they live, where they come from, and when they count as installed.
//!
//! The app downloads them once (`curl.exe`), checks each SHA-256 and writes [`VERIFIED`]. The
//! revision is pinned: a later push to the model's repository changes nothing here.

use std::path::{Path, PathBuf};

use crate::{Error, Result, vault};

/// Folder name of this model under `%LOCALAPPDATA%\piikey\models`: the model, then its short
/// pinned revision. A new model or revision gets a new folder, so the old one is never half-used.
pub const MODEL_ID: &str = "eu-pii-v2-5e61416";

/// File name of the ONNX graph.
pub const GRAPH_FILE: &str = "model_quantized.onnx";

/// File name of the tokenizer.
pub const TOKENIZER_FILE: &str = "tokenizer.json";

/// One file of the model.
#[derive(Debug, Clone, Copy)]
pub struct ModelFile {
    /// File name inside the model folder.
    pub name: &'static str,
    /// Where to download it from (the pinned revision).
    pub url: &'static str,
    /// Exact size in bytes.
    pub size: u64,
    /// Lowercase hex SHA-256.
    pub sha256: &'static str,
}

/// What the model needs: the INT8 ONNX graph and its tokenizer.
pub const FILES: [ModelFile; 2] = [
    ModelFile {
        name: GRAPH_FILE,
        url: "https://huggingface.co/bardsai/eu-pii-anonimization-multilang-v2/resolve/5e61416e77675881185767fc0c67759d48b35592/onnx/model_quantized.onnx",
        size: 308_618_574,
        sha256: "1ee975af537a3ae507769703c03fc83880cce7e2706bc6d2dc1fd9db861acfa1",
    },
    ModelFile {
        name: TOKENIZER_FILE,
        url: "https://huggingface.co/bardsai/eu-pii-anonimization-multilang-v2/resolve/5e61416e77675881185767fc0c67759d48b35592/tokenizer.json",
        size: 34_363_188,
        sha256: "609d8f4c067cd3950f88594c5a802616cea245823836ef5848ee4fc40aab5b6f",
    },
];

/// Marker file, written once every file has the right size and SHA-256.
pub const VERIFIED: &str = "verified";

/// What the first load found out about this machine, so later loads skip the measuring: `hybrid`
/// (the graphics card is fast enough to help: big calls use it next to the processor) or `cpu`
/// (it is not, or does not work). Delete the file to measure again, for example after a new
/// graphics card, or write one of the two words into it to choose by hand. A `gpu` written by an
/// older version reads as `hybrid`.
pub const DEVICE_FILE: &str = "device.cfg";

/// `%LOCALAPPDATA%\piikey\models\<MODEL_ID>`, next to the default vault. Not created.
///
/// # Errors
/// `VaultPathUnavailable` when `LOCALAPPDATA` is unset; `Io` when the piikey folder cannot be
/// created.
pub fn default_dir() -> Result<PathBuf> {
    let vault = vault::default_path()?;
    let base = vault.parent().ok_or(Error::VaultPathUnavailable)?;
    Ok(base.join("models").join(MODEL_ID))
}

/// True when `dir` holds every file at its exact size and the [`VERIFIED`] marker. A download
/// that was cut off or not yet checked does not count.
#[must_use]
pub fn is_installed(dir: &Path) -> bool {
    installed(dir, &FILES)
}

fn installed(dir: &Path, files: &[ModelFile]) -> bool {
    dir.join(VERIFIED).is_file()
        && files.iter().all(|file| {
            std::fs::metadata(dir.join(file.name))
                .is_ok_and(|meta| meta.is_file() && meta.len() == file.size)
        })
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    const SMALL: [ModelFile; 2] = [
        ModelFile {
            name: "a.bin",
            url: "",
            size: 3,
            sha256: "",
        },
        ModelFile {
            name: "b.bin",
            url: "",
            size: 5,
            sha256: "",
        },
    ];

    /// A fresh folder under the system temp dir, removed on drop.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("piikey-ner-files-{tag}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&dir);
            let _ = fs::create_dir_all(&dir);
            Self(dir)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_pinned_files_are_well_formed() {
        for file in &FILES {
            assert!(
                file.url.starts_with("https://huggingface.co/"),
                "{}",
                file.name
            );
            assert!(
                file.url
                    .contains("/resolve/5e61416e77675881185767fc0c67759d48b35592/"),
                "{} must stay pinned to a revision",
                file.name
            );
            assert!(file.url.ends_with(file.name), "{}", file.name);
            assert_eq!(file.sha256.len(), 64, "{}", file.name);
            assert!(
                file.sha256
                    .bytes()
                    .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
                "{}",
                file.name
            );
            assert!(file.size > 0);
        }
        assert!(MODEL_ID.ends_with("5e61416"));
    }

    #[test]
    fn the_default_dir_sits_beside_the_vault() -> crate::Result<()> {
        // Needs LOCALAPPDATA, which every Windows session has.
        let dir = default_dir()?;
        let vault = vault::default_path()?;
        assert_eq!(dir.parent().and_then(Path::parent), vault.parent());
        assert!(dir.ends_with(Path::new("models").join(MODEL_ID)));
        Ok(())
    }

    #[test]
    fn a_model_counts_as_installed_only_when_complete_and_verified() -> crate::Result<()> {
        let scratch = Scratch::new("installed");
        let dir = &scratch.0;
        assert!(!installed(dir, &SMALL), "empty folder");

        fs::write(dir.join("a.bin"), [0u8; 3])?;
        fs::write(dir.join("b.bin"), [0u8; 5])?;
        assert!(!installed(dir, &SMALL), "no verified marker yet");

        fs::write(dir.join(VERIFIED), b"")?;
        assert!(installed(dir, &SMALL));

        fs::write(dir.join("b.bin"), [0u8; 4])?;
        assert!(!installed(dir, &SMALL), "a file of the wrong size");

        fs::write(dir.join("b.bin"), [0u8; 5])?;
        fs::remove_file(dir.join("a.bin"))?;
        assert!(!installed(dir, &SMALL), "a missing file");
        Ok(())
    }

    #[test]
    fn the_real_file_list_is_not_satisfied_by_an_empty_folder() {
        let scratch = Scratch::new("empty");
        assert!(!is_installed(&scratch.0));
    }
}
