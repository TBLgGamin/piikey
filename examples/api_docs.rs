//! `cargo api-docs`: the reference of the API, written from the code.
//!
//! - no argument: writes `docs/api/openapi.json` and `docs/api/README.md`, with the prose of
//!   `docs/api/prose.toml` as it is on disk. A file that is already right is left alone.
//! - `--check-prose`: prints the prose that is out of date (an operation changed since its prose
//!   was reviewed, or prose for what is no operation) and exits with 1 if there is any. The
//!   pre-commit hook runs it; it never accepts anything by itself.
//! - `--accept <operation|intro|all>`: after reading the prose, brings its fingerprint up to
//!   date: only the fingerprints of `prose.toml` change, never its text. Then writes the files.
//!
//! Exit codes: 0 done, 1 prose out of date, 2 anything else went wrong.

use std::{env, fs, path::Path, process::ExitCode};

use piikey::api::openapi::{self, MARKDOWN_PATH, PROSE_PATH, SPEC_PATH};

const USAGE: &str = "usage: cargo api-docs [--check-prose | --accept <operation|intro|all>]";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let done = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => write_reference(root).map(|()| ExitCode::SUCCESS),
        ["--check-prose"] => check_prose(root),
        ["--accept", which] => accept(root, which).map(|()| ExitCode::SUCCESS),
        _ => Err(USAGE.to_owned()),
    };
    done.unwrap_or_else(|message| {
        eprintln!("api-docs: {message}");
        ExitCode::from(2)
    })
}

/// What `path` (from the root of the repository) holds, with lines ended by `\n`.
fn read(root: &Path, path: &str) -> Result<String, String> {
    let text = fs::read_to_string(root.join(path)).map_err(|error| format!("{path}: {error}"))?;
    Ok(text.replace("\r\n", "\n"))
}

/// Writes `text` to `path` (from the root of the repository) unless it is there already.
fn write(root: &Path, path: &str, text: &str) -> Result<(), String> {
    if fs::read_to_string(root.join(path)).is_ok_and(|have| have.replace("\r\n", "\n") == text) {
        return Ok(());
    }
    fs::write(root.join(path), text).map_err(|error| format!("{path}: {error}"))?;
    println!("api-docs: wrote {path}");
    Ok(())
}

/// Both generated files, from the code and the prose on disk.
fn write_reference(root: &Path) -> Result<(), String> {
    let prose = read(root, PROSE_PATH)?;
    let reference = openapi::generate(&prose).map_err(|error| error.to_string())?;
    write(root, SPEC_PATH, &reference.openapi)?;
    write(root, MARKDOWN_PATH, &reference.markdown)
}

/// Prints what is wrong with the prose; 1 when anything is.
fn check_prose(root: &Path) -> Result<ExitCode, String> {
    let prose = read(root, PROSE_PATH)?;
    let review = openapi::review(&prose).map_err(|error| error.to_string())?;
    if !review.missing.is_empty() {
        println!(
            "api-docs: note: no prose for {} (allowed): {}",
            review.missing.len(),
            review.missing.join(", ")
        );
    }
    for problem in &review.problems {
        println!("api-docs: {problem}");
    }
    Ok(if review.problems.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    })
}

/// Brings the fingerprint of `which` up to date, then writes the files with the prose as it is.
fn accept(root: &Path, which: &str) -> Result<(), String> {
    let prose = read(root, PROSE_PATH)?;
    let accepted = openapi::accept(&prose, which).map_err(|error| error.to_string())?;
    write(root, PROSE_PATH, &accepted)?;
    write_reference(root)
}
