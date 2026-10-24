//! A result as a person reads it: lines and tables. `--json` bypasses all of this.
//!
//! Which view a result gets is chosen from the request, before it is sent, by an exhaustive
//! match: an operation added to the API cannot be forgotten here.

use std::{
    io::{self, Write},
    path::PathBuf,
};

use piikey::{
    api::{
        ApiError, Request,
        reply::{
            AccountInfo, AccountRemoved, Accounts, Entries, Exported, Folders, Forgotten, Found,
            InventoryStatus, Kind, Model, ModelState, Nodes, Protection, Records, Reported,
            Scanned, Spans, Status, Texts, Token, Written,
        },
    },
    detect::EntityKind,
    inventory::{Entry, Status as FileStatus, Totals},
    policy::Policy,
};
use serde::Deserialize;
use serde_json::Value;

use super::{Fail, parse::FailOn};

/// How a request's result is printed.
#[derive(Debug, PartialEq, Eq)]
pub enum View {
    /// `anonymize` and `deanonymize` of stdin: the text, as it is.
    Text,
    /// `scan` of stdin.
    Spans,
    /// `scan` of files.
    Files,
    /// `anonymize` and `deanonymize` of files.
    Written,
    /// `subject`, with the values that were searched for.
    Subject(Vec<String>),
    /// `vault list`, from the record number `offset`.
    Records {
        offset: usize,
    },
    Forgotten,
    Exported,
    Report,
    InventoryStatus,
    /// `inventory list`, from the entry number `offset`.
    Entries {
        offset: usize,
    },
    Nodes,
    Rescanned,
    Settings,
    Kinds,
    Model,
    Downloaded,
    Token,
    Status,
    Protection,
    /// `account list`.
    Accounts,
    /// `account add` and `account connect`: one account.
    Account,
    AccountRemoved,
    /// `account browse`.
    Folders,
    /// Nothing better than the JSON.
    Json,
}

impl View {
    /// The view of the result of `request`.
    #[must_use]
    pub fn of(request: &Request) -> Self {
        match request {
            Request::Anonymize { .. } | Request::Deanonymize { .. } => Self::Text,
            Request::ScanText { .. } => Self::Spans,
            Request::ScanFiles { .. } => Self::Files,
            Request::AnonymizeFiles { .. } | Request::DeanonymizeFiles { .. } => Self::Written,
            Request::SubjectSearch { values, .. } => Self::Subject(values.clone()),
            Request::VaultList { offset, .. } => Self::Records { offset: *offset },
            Request::VaultForget { .. } | Request::VaultWipe { .. } => Self::Forgotten,
            Request::VaultExport { .. } => Self::Exported,
            Request::InventoryStatus => Self::InventoryStatus,
            Request::InventoryList { offset, .. } => Self::Entries { offset: *offset },
            Request::InventoryTree { .. } => Self::Nodes,
            Request::InventoryRescan => Self::Rescanned,
            Request::InventoryReport { .. } => Self::Report,
            Request::SettingsGet | Request::SettingsSet { .. } => Self::Settings,
            Request::AccountsList => Self::Accounts,
            Request::AccountAdd { .. } | Request::AccountConnect { .. } => Self::Account,
            Request::AccountRemove { .. } => Self::AccountRemoved,
            Request::AccountBrowse { .. } => Self::Folders,
            Request::Kinds => Self::Kinds,
            Request::ModelStatus => Self::Model,
            Request::ModelDownload => Self::Downloaded,
            Request::ApiToken { .. } => Self::Token,
            Request::Status => Self::Status,
            Request::Protection { .. } => Self::Protection,
            Request::ExplorerScan { .. } | Request::ShowWindow => Self::Json,
        }
    }
}

/// Prints `value`, the result of a request that had `view`, to `out`. Items that failed within
/// an operation that went on (a file that could not be read) go to `err`, after the rest.
///
/// # Errors
/// A reply that does not have the shape the operation promises, or a write that fails.
pub fn print(
    view: &View,
    value: &Value,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> Result<(), Fail> {
    match view {
        View::Text => text(value, out),
        View::Spans => spans(value, out),
        View::Files => files(value, out, err),
        View::Written => written(value, out, err),
        View::Subject(values) => subject(values, value, out),
        View::Records { offset } => records(*offset, value, out),
        View::Forgotten => forgotten(value, out),
        View::Exported => exported(value, out),
        View::Report => report(value, out),
        View::InventoryStatus => inventory_status(value, out),
        View::Entries { offset } => entries(*offset, value, out),
        View::Nodes => nodes(value, out),
        View::Rescanned => rescanned(value, out),
        View::Settings => settings(value, out),
        View::Kinds => kinds(value, out),
        View::Model => model(value, out),
        View::Downloaded => Ok(writeln!(out, "the detection model is downloaded")?),
        View::Token => token(value, out),
        View::Status => status(value, out),
        View::Protection => protection(value, out),
        View::Accounts => accounts(value, out),
        View::Account => account(value, out),
        View::AccountRemoved => account_removed(value, out),
        View::Folders => folders(value, out),
        View::Json => Ok(writeln!(out, "{}", pretty(value))?),
    }
}

/// The result as indented JSON.
#[must_use]
pub fn pretty(value: &Value) -> String {
    format!("{value:#}")
}

/// How a result bears on the exit code of the command.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Verdict {
    /// A value of a kind `--fail-on` fails on was found.
    pub found: bool,
    /// Files that could not be read or written.
    pub failed: usize,
}

/// The [`Verdict`] on `value`, the result of a request that had `view`. Only scans and writes
/// have one: the reply of any other view is not looked at, so it is never an error there.
///
/// # Errors
/// A reply that does not have the shape the operation promises.
pub fn verdict(view: &View, value: &Value, fail_on: Option<&FailOn>) -> Result<Verdict, Fail> {
    match view {
        // Without a gate a found value is no news, so the reply is not even read.
        View::Spans => Ok(Verdict {
            found: match fail_on {
                Some(fail_on) => reply::<Spans>(value)?
                    .results
                    .iter()
                    .flatten()
                    .any(|span| fail_on.matches(&span.kind)),
                None => false,
            },
            failed: 0,
        }),
        View::Files => {
            let scanned = reply::<Scanned>(value)?;
            let found = fail_on.is_some_and(|fail_on| {
                scanned
                    .files
                    .iter()
                    .flat_map(|file| &file.counts)
                    .any(|&(kind, n)| n > 0 && fail_on.matches(kind.as_str()))
            });
            let failed = scanned
                .files
                .iter()
                .filter(|file| matches!(file.status, FileStatus::Failed(_)))
                .count();
            Ok(Verdict { found, failed })
        }
        View::Written => Ok(Verdict {
            found: false,
            failed: reply::<Written>(value)?.failed.len(),
        }),
        _ => Ok(Verdict::default()),
    }
}

/// `value` as the reply `T`.
fn reply<'a, T: Deserialize<'a>>(value: &'a Value) -> Result<T, Fail> {
    T::deserialize(value).map_err(|e| unexpected(&e.to_string()))
}

fn text(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let texts = reply::<Texts>(value)?.texts;
    let [text] = texts.as_slice() else {
        return Err(unexpected("not exactly one text"));
    };
    // Not a line: the text is the output, as it was given, down to its last byte.
    out.write_all(text.as_bytes())?;
    Ok(())
}

fn spans(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let spans = reply::<Spans>(value)?
        .results
        .into_iter()
        .next()
        .unwrap_or_default();
    if spans.is_empty() {
        writeln!(out, "no personal data found")?;
        return Ok(());
    }
    let rows: Vec<Vec<String>> = spans
        .iter()
        .map(|span| {
            vec![
                span.kind.clone(),
                format!("{}-{}", span.start, span.end),
                one_line(&span.value),
            ]
        })
        .collect();
    table(out, &["KIND", "BYTES", "VALUE"], &[], &rows)?;
    writeln!(out, "{} found", plural(count(spans.len()), "value"))?;
    Ok(())
}

fn files(value: &Value, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Fail> {
    let files = reply::<Scanned>(value)?.files;
    // The files that hold something, the one with the most first.
    let mut holding: Vec<&Entry> = files.iter().filter(|file| file.hits() > 0).collect();
    holding.sort_by(|a, b| b.hits().cmp(&a.hits()).then_with(|| a.path.cmp(&b.path)));
    if !holding.is_empty() {
        scan_table(out, holding.iter().copied())?;
    }
    let hits: u64 = holding.iter().map(|file| file.hits()).sum();
    let mut skipped = 0;
    let mut failures = Vec::new();
    for file in &files {
        match &file.status {
            FileStatus::Ok => {}
            FileStatus::Unsupported | FileStatus::TooLarge => skipped += 1,
            FileStatus::Failed(why) => failures.push((file, why)),
        }
    }
    let mut summary = vec![format!("{} scanned", plural(count(files.len()), "file"))];
    summary.push(if hits == 0 {
        "no personal data found".to_owned()
    } else {
        format!(
            "{} with personal data, {} found",
            holding.len(),
            plural(hits, "value")
        )
    });
    if skipped > 0 {
        summary.push(format!(
            "{skipped} not read (unsupported format or too big)"
        ));
    }
    if !failures.is_empty() {
        summary.push(format!("{} failed", failures.len()));
    }
    writeln!(out, "{}", summary.join(", "))?;
    // What went wrong comes after the table even when both end up on the same screen.
    out.flush()?;
    for (file, why) in failures {
        let why = if why.is_empty() {
            "could not be read"
        } else {
            why.as_str()
        };
        writeln!(err, "piikey-cli: {}: {why}", file.path.display())?;
    }
    Ok(())
}

/// `HITS FOUND FILE`, a row per file.
fn scan_table<'a>(
    out: &mut dyn Write,
    files: impl IntoIterator<Item = &'a Entry>,
) -> io::Result<()> {
    let rows: Vec<Vec<String>> = files
        .into_iter()
        .map(|file| {
            vec![
                file.hits().to_string(),
                counts(&file.counts),
                file.path.display().to_string(),
            ]
        })
        .collect();
    table(out, &["HITS", "FOUND", "FILE"], &[0], &rows)
}

fn unexpected(what: &str) -> Fail {
    Fail::Api(ApiError::internal(format!("unexpected reply: {what}")))
}

fn written(value: &Value, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<Written>(value)?;
    for moved in &reply.written {
        writeln!(out, "{} -> {}", moved.input, moved.output)?;
    }
    writeln!(
        out,
        "{} written{}",
        plural(count(reply.written.len()), "file"),
        if reply.failed.is_empty() {
            String::new()
        } else {
            format!(", {} failed", reply.failed.len())
        }
    )?;
    out.flush()?;
    for failed in &reply.failed {
        writeln!(err, "piikey-cli: {}: {}", failed.input, failed.error)?;
    }
    Ok(())
}

fn subject(values: &[String], value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let matches = reply::<Found>(value)?.matches;
    if matches.is_empty() {
        writeln!(out, "no file mentions these values")?;
        return Ok(());
    }
    let rows: Vec<Vec<String>> = matches
        .iter()
        .map(|m| {
            let named: Vec<String> = m
                .values
                .iter()
                .map(|&i| {
                    values
                        .get(i)
                        .map_or_else(|| format!("#{i}"), |v| one_line(v))
                })
                .collect();
            vec![
                m.count.to_string(),
                named.join(", "),
                m.path.display().to_string(),
            ]
        })
        .collect();
    table(out, &["COUNT", "VALUES", "FILE"], &[0], &rows)?;
    let mentioning = count(matches.len());
    let verb = if mentioning == 1 {
        "mentions"
    } else {
        "mention"
    };
    writeln!(out, "{} {verb} them", plural(mentioning, "file"))?;
    Ok(())
}

fn records(offset: usize, value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<Records>(value)?;
    if reply.records.is_empty() {
        writeln!(out, "no records")?;
        return Ok(());
    }
    let rows: Vec<Vec<String>> = reply
        .records
        .iter()
        .map(|r| vec![r.kind.clone(), one_line(&r.original), one_line(&r.proxy)])
        .collect();
    table(out, &["KIND", "VALUE", "STAND-IN"], &[], &rows)?;
    footer(out, offset, reply.records.len(), reply.total, "record")?;
    Ok(())
}

/// `shown` items from the number `offset` of `total`, and how to get the rest. `noun` is the
/// singular.
fn footer(
    out: &mut dyn Write,
    offset: usize,
    shown: usize,
    total: usize,
    noun: &str,
) -> io::Result<()> {
    let next = offset + shown;
    if offset == 0 && next >= total {
        writeln!(out, "{}", plural(count(total), noun))
    } else if next < total {
        writeln!(
            out,
            "{noun}s {}-{next} of {total}; the next ones follow with --offset {next}",
            offset + 1
        )
    } else {
        writeln!(out, "{noun}s {}-{next} of {total}", offset + 1)
    }
}

fn forgotten(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    match reply::<Forgotten>(value)?.forgotten {
        0 => writeln!(out, "no records removed")?,
        n => writeln!(out, "forgot {}", plural(count(n), "record"))?,
    }
    Ok(())
}

fn exported(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<Exported>(value)?;
    writeln!(
        out,
        "wrote {} to {}",
        plural(count(reply.records), "record"),
        reply.path
    )?;
    Ok(())
}

fn report(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<Reported>(value)?;
    writeln!(
        out,
        "wrote {} to {}",
        plural(count(reply.rows), "row"),
        reply.path
    )?;
    Ok(())
}

fn inventory_status(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<InventoryStatus>(value)?;
    let list = |paths: &[String]| {
        if paths.is_empty() {
            "none".to_owned()
        } else {
            paths.join(", ")
        }
    };
    let scan = reply.scanning.map_or_else(
        || "not running".to_owned(),
        |s| format!("running, {} of {} files", s.done, s.total),
    );
    pairs(
        out,
        &[
            ("folders", list(&reply.roots)),
            ("monitored", list(&reply.monitored)),
            ("files", reply.files.to_string()),
            ("with personal data", reply.files_with_pii.to_string()),
            ("values found", reply.hits.to_string()),
            ("scan", scan),
        ],
    )?;
    Ok(())
}

fn entries(offset: usize, value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<Entries>(value)?;
    if reply.entries.is_empty() {
        writeln!(out, "no files with personal data in the inventory")?;
        return Ok(());
    }
    scan_table(out, &reply.entries)?;
    footer(out, offset, reply.entries.len(), reply.total, "file")?;
    Ok(())
}

fn nodes(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let nodes = reply::<Nodes>(value)?.nodes;
    if nodes.is_empty() {
        writeln!(out, "nothing with personal data here")?;
        return Ok(());
    }
    let rows: Vec<Vec<String>> = nodes
        .iter()
        .map(|node| {
            let path = node.path.display().to_string();
            let place = if node.is_dir {
                format!("{}\\", path.trim_end_matches('\\'))
            } else {
                path
            };
            vec![
                node.hits.to_string(),
                node.files.to_string(),
                counts(&node.counts),
                place,
            ]
        })
        .collect();
    table(out, &["HITS", "FILES", "FOUND", "PATH"], &[0, 1], &rows)?;
    Ok(())
}

fn rescanned(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let totals = reply::<Totals>(value)?;
    writeln!(
        out,
        "scanned: the inventory holds {}, {} with personal data, {} found",
        plural(totals.files, "file"),
        totals.files_with_pii,
        plural(totals.hits, "value")
    )?;
    Ok(())
}

/// The settings as `KEY=VALUE` lines: what `settings set` takes.
fn settings(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let settings = reply::<Policy>(value)?;
    writeln!(out, "highlight={}", settings.highlight.as_str())?;
    writeln!(out, "explorer_menu={}", settings.explorer_menu)?;
    writeln!(out, "background={}", settings.background)?;
    writeln!(out, "http_api={}", settings.http_api)?;
    writeln!(out, "http_port={}", settings.http_port)?;
    let paths = |paths: &[PathBuf]| -> Vec<String> {
        paths.iter().map(|p| p.display().to_string()).collect()
    };
    let lists = [
        ("site", settings.sites),
        ("program", settings.programs),
        (
            "disabled_kind",
            settings
                .disabled_kinds
                .iter()
                .map(|kind| kind.as_str().to_owned())
                .collect(),
        ),
        ("inventory_root", paths(&settings.inventory_roots)),
        ("monitor_root", paths(&settings.monitored_roots)),
    ];
    for (key, list) in lists {
        for item in list {
            writeln!(out, "{key}={item}")?;
        }
    }
    Ok(())
}

fn kinds(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let kinds = reply::<Vec<Kind>>(value)?;
    let rows: Vec<Vec<String>> = kinds
        .iter()
        .map(|k| {
            vec![
                k.kind.clone(),
                k.label.clone(),
                k.group.clone(),
                (if k.enabled { "yes" } else { "no" }).to_owned(),
            ]
        })
        .collect();
    table(out, &["KIND", "LABEL", "GROUP", "ON"], &[], &rows)?;
    Ok(())
}

fn model(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let model = reply::<Model>(value)?;
    pairs(
        out,
        &[
            ("model", model_phrase(&model)),
            ("folder", model.dir.clone()),
        ],
    )?;
    Ok(())
}

fn model_phrase(model: &Model) -> String {
    const MB: u64 = 1024 * 1024;
    if let Some(download) = &model.downloading {
        return format!(
            "downloading, {} of {} MB",
            download.done / MB,
            download.total / MB
        );
    }
    match (model.state, model.device, &model.error) {
        (ModelState::Missing, ..) => "not downloaded (piikey-cli model download)".to_owned(),
        (ModelState::Unloaded, ..) => "downloaded, loads when it is needed".to_owned(),
        (ModelState::Ready, Some(device), _) => format!("ready ({})", device.as_str()),
        (ModelState::Ready, None, _) => "ready".to_owned(),
        (ModelState::Failed, _, Some(error)) => format!("failed: {error}"),
        (ModelState::Failed, _, None) => "failed".to_owned(),
    }
}

/// Just the token, so `$(piikey-cli token)` is the token.
fn token(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    writeln!(out, "{}", reply::<Token>(value)?.token)?;
    Ok(())
}

fn status(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let status = reply::<Status>(value)?;
    let protection = match status.protection {
        Some(on) => on_off(on).to_owned(),
        None => "unknown (it is the app's)".to_owned(),
    };
    pairs(
        out,
        &[
            ("version", status.version.clone()),
            (
                "app",
                if status.app { "running" } else { "not running" }.to_owned(),
            ),
            ("protection", protection),
            ("vault", plural(status.vault_records, "record")),
            ("model", model_phrase(&status.model)),
            ("highlight", status.highlight.as_str().to_owned()),
            ("explorer menu", on_off(status.explorer_menu).to_owned()),
            ("monitoring", on_off(status.monitoring).to_owned()),
            ("HTTP API", on_off(status.http_api).to_owned()),
        ],
    )?;
    Ok(())
}

fn protection(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let on = reply::<Protection>(value)?.protection;
    writeln!(out, "protection is {}", on_off(on))?;
    Ok(())
}

/// The way an account signs in, as `account add --mode` spells it.
fn way(info: &AccountInfo) -> String {
    serde_json::to_value(&info.sign_in)
        .ok()
        .and_then(|value| value.get("mode").and_then(Value::as_str).map(str::to_owned))
        .unwrap_or_default()
}

fn account_state(info: &AccountInfo) -> &'static str {
    if info.connected {
        "connected"
    } else {
        "not connected"
    }
}

fn accounts(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let accounts = reply::<Accounts>(value)?.accounts;
    if accounts.is_empty() {
        writeln!(
            out,
            "no cloud accounts (piikey-cli account add connects one)"
        )?;
        return Ok(());
    }
    let rows: Vec<Vec<String>> = accounts
        .iter()
        .map(|info| {
            vec![
                info.id.clone(),
                info.provider.name().to_owned(),
                info.label.clone(),
                way(info),
                account_state(info).to_owned(),
                info.path.clone(),
            ]
        })
        .collect();
    table(
        out,
        &["ID", "SERVICE", "NAME", "SIGN-IN", "STATUS", "PATH"],
        &[],
        &rows,
    )?;
    Ok(())
}

fn account(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let info = reply::<AccountInfo>(value)?;
    pairs(
        out,
        &[
            ("id", info.id.clone()),
            ("service", info.provider.name().to_owned()),
            ("name", info.label.clone()),
            ("sign-in", way(&info)),
            ("status", account_state(&info).to_owned()),
            ("path", info.path.clone()),
        ],
    )?;
    if !info.connected {
        writeln!(
            out,
            "not connected yet: piikey-cli account connect {} signs in",
            info.id
        )?;
    }
    Ok(())
}

fn account_removed(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let removed = reply::<AccountRemoved>(value)?;
    writeln!(out, "removed the account {}", removed.id)?;
    for location in &removed.locations {
        writeln!(out, "took {location} off the locations")?;
    }
    writeln!(out, "forgot {}", plural(removed.forgotten, "file"))?;
    Ok(())
}

fn folders(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let folders = reply::<Folders>(value)?.folders;
    if folders.is_empty() {
        writeln!(out, "no folders here")?;
        return Ok(());
    }
    let rows: Vec<Vec<String>> = folders
        .iter()
        .map(|folder| vec![folder.name.clone(), folder.path.clone()])
        .collect();
    table(out, &["NAME", "PATH"], &[], &rows)?;
    Ok(())
}

fn on_off(on: bool) -> &'static str {
    if on { "on" } else { "off" }
}

/// `1 file`, `2 files`.
fn plural(n: u64, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

fn count(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// `email: 3, phone_number: 1`, in the order given (the most first); a zero is left out.
fn counts(counts: &[(EntityKind, u32)]) -> String {
    let parts: Vec<String> = counts
        .iter()
        .filter(|&&(_, n)| n > 0)
        .map(|(kind, n)| format!("{}: {n}", kind.as_str()))
        .collect();
    parts.join(", ")
}

/// `text` on one line: line breaks and other control characters are written out.
fn one_line(text: &str) -> String {
    let mut line = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '\n' => line.push_str("\\n"),
            '\r' => line.push_str("\\r"),
            '\t' => line.push_str("\\t"),
            c if c.is_control() => line.extend(c.escape_unicode()),
            c => line.push(c),
        }
    }
    line
}

/// Rows of cells under a header, the columns as wide as their widest cell; the columns in
/// `right` are right-aligned (numbers). The last column is not padded.
fn table(
    out: &mut dyn Write,
    head: &[&str],
    right: &[usize],
    rows: &[Vec<String>],
) -> io::Result<()> {
    let widths: Vec<usize> = head
        .iter()
        .enumerate()
        .map(|(col, name)| {
            rows.iter()
                .filter_map(|row| row.get(col))
                .map(|cell| cell.chars().count())
                .fold(name.chars().count(), usize::max)
        })
        .collect();
    let line = |cells: &[&str]| {
        let last = cells.len().saturating_sub(1);
        let mut line = String::new();
        for (col, cell) in cells.iter().enumerate() {
            if col > 0 {
                line.push_str("  ");
            }
            let pad = widths
                .get(col)
                .copied()
                .unwrap_or_default()
                .saturating_sub(cell.chars().count());
            if right.contains(&col) {
                line.push_str(&" ".repeat(pad));
                line.push_str(cell);
            } else {
                line.push_str(cell);
                if col != last {
                    line.push_str(&" ".repeat(pad));
                }
            }
        }
        line
    };
    writeln!(out, "{}", line(head))?;
    for row in rows {
        let cells: Vec<&str> = row.iter().map(String::as_str).collect();
        writeln!(out, "{}", line(&cells))?;
    }
    Ok(())
}

/// `name  value` lines with the values in one column.
fn pairs(out: &mut dyn Write, rows: &[(&str, String)]) -> io::Result<()> {
    let width = rows
        .iter()
        .map(|(key, _)| key.chars().count())
        .max()
        .unwrap_or_default();
    for (key, value) in rows {
        writeln!(out, "{key:<width$}  {value}")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
