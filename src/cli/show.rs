//! A result as a person reads it: lines and tables. `--json` bypasses all of this.
//!
//! Which view a result gets is chosen from the request, before it is sent, by an exhaustive
//! match: an operation added to the API cannot be forgotten here.

use std::{
    collections::BTreeMap,
    io::{self, Write},
};

use piikey::api::{ApiError, Request};
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
    Protection {
        on: bool,
    },
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
            Request::Kinds => Self::Kinds,
            Request::ModelStatus => Self::Model,
            Request::ModelDownload => Self::Downloaded,
            Request::ApiToken { .. } => Self::Token,
            Request::Status => Self::Status,
            Request::Protection { on } => Self::Protection { on: *on },
            Request::ExplorerScan { .. } => Self::Json,
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
        View::Protection { on } => Ok(writeln!(out, "protection is {}", on_off(*on))?),
        View::Json => Ok(writeln!(out, "{}", pretty(value))?),
    }
}

/// The result as indented JSON.
#[must_use]
pub fn pretty(value: &Value) -> String {
    // A `Value` always serializes; its own text is the fallback for the case that never is.
    serde_json::to_string_pretty(value).unwrap_or_else(|_| value.to_string())
}

/// Whether a scan found a value that `fail_on` fails on. Other views never do.
///
/// # Errors
/// A reply that does not have the shape the operation promises.
pub fn found(fail_on: &FailOn, view: &View, value: &Value) -> Result<bool, Fail> {
    Ok(match view {
        View::Spans => reply::<SpansReply>(value)?
            .results
            .iter()
            .flatten()
            .any(|span| fail_on.matches(&span.kind)),
        View::Files => reply::<FilesReply>(value)?.files.iter().any(|file| {
            file.counts
                .iter()
                .any(|(kind, &n)| n > 0 && fail_on.matches(kind))
        }),
        _ => false,
    })
}

/// How many items of an operation that went on failed: files that could not be read or written.
///
/// # Errors
/// A reply that does not have the shape the operation promises.
pub fn failed(view: &View, value: &Value) -> Result<usize, Fail> {
    Ok(match view {
        View::Files => reply::<FilesReply>(value)?
            .files
            .iter()
            .filter(|file| file.status == "failed")
            .count(),
        View::Written => reply::<WrittenReply>(value)?.failed.len(),
        _ => 0,
    })
}

#[derive(Deserialize)]
struct TextsReply {
    texts: Vec<String>,
}

#[derive(Deserialize)]
struct SpansReply {
    results: Vec<Vec<SpanReply>>,
}

#[derive(Deserialize)]
struct SpanReply {
    start: usize,
    end: usize,
    kind: String,
    value: String,
}

#[derive(Deserialize)]
struct FilesReply {
    files: Vec<FileReply>,
}

/// A scanned file, and an inventory entry, which is the same plus what the scan ran into.
#[derive(Deserialize)]
struct FileReply {
    path: String,
    status: String,
    #[serde(default)]
    error: Option<String>,
    #[serde(default)]
    counts: BTreeMap<String, u64>,
}

impl FileReply {
    fn hits(&self) -> u64 {
        self.counts.values().sum()
    }
}

#[derive(Deserialize)]
struct WrittenReply {
    written: Vec<MovedReply>,
    failed: Vec<FailedReply>,
}

#[derive(Deserialize)]
struct MovedReply {
    input: String,
    output: String,
}

#[derive(Deserialize)]
struct FailedReply {
    input: String,
    error: String,
}

#[derive(Deserialize)]
struct SubjectReply {
    matches: Vec<MatchReply>,
}

#[derive(Deserialize)]
struct MatchReply {
    path: String,
    values: Vec<usize>,
    count: u64,
}

#[derive(Deserialize)]
struct RecordsReply {
    records: Vec<RecordReply>,
    total: usize,
}

#[derive(Deserialize)]
struct RecordReply {
    kind: String,
    original: String,
    proxy: String,
}

#[derive(Deserialize)]
struct ForgottenReply {
    forgotten: u64,
}

#[derive(Deserialize)]
struct ExportedReply {
    records: u64,
    path: String,
}

#[derive(Deserialize)]
struct ReportReply {
    rows: u64,
    path: String,
}

#[derive(Deserialize)]
struct InventoryStatusReply {
    enabled: bool,
    roots: Vec<String>,
    files: u64,
    files_with_pii: u64,
    hits: u64,
    #[serde(default)]
    scanning: Option<ProgressReply>,
}

/// How far a scan or a download is: `done` of `total`.
#[derive(Deserialize)]
struct ProgressReply {
    done: u64,
    total: u64,
}

#[derive(Deserialize)]
struct EntriesReply {
    entries: Vec<FileReply>,
    total: usize,
}

#[derive(Deserialize)]
struct NodesReply {
    nodes: Vec<NodeReply>,
}

#[derive(Deserialize)]
struct NodeReply {
    path: String,
    name: String,
    is_dir: bool,
    hits: u64,
    files: u64,
    #[serde(default)]
    counts: BTreeMap<String, u64>,
}

#[derive(Deserialize)]
struct TotalsReply {
    files: u64,
    files_with_pii: u64,
    hits: u64,
}

/// The saved settings, as the `guard.cfg` keys name them.
#[derive(Deserialize)]
struct SettingsReply {
    highlight: String,
    explorer_menu: bool,
    inventory: bool,
    http_api: bool,
    http_port: u16,
    #[serde(default)]
    sites: Vec<String>,
    #[serde(default)]
    programs: Vec<String>,
    #[serde(default)]
    disabled_kinds: Vec<String>,
    #[serde(default)]
    inventory_roots: Vec<String>,
    #[serde(default)]
    inventory_exclude: Vec<String>,
}

#[derive(Deserialize)]
struct KindReply {
    kind: String,
    label: String,
    group: String,
    enabled: bool,
}

#[derive(Deserialize)]
struct ModelReply {
    state: String,
    #[serde(default)]
    device: Option<String>,
    #[serde(default)]
    error: Option<String>,
    /// Only the app says it: the download it is running, in bytes.
    #[serde(default)]
    downloading: Option<ProgressReply>,
    dir: String,
}

#[derive(Deserialize)]
struct TokenReply {
    token: String,
}

#[derive(Deserialize)]
struct StatusReply {
    app: bool,
    #[serde(default)]
    protection: Option<bool>,
    version: String,
    vault_records: u64,
    model: ModelReply,
    highlight: String,
    #[serde(flatten)]
    features: Features,
}

/// The on/off switches of the features that sit in the status next to the rest.
#[derive(Deserialize)]
struct Features {
    explorer_menu: bool,
    inventory: bool,
    http_api: bool,
}

/// `value` as the reply `T`.
fn reply<'a, T: Deserialize<'a>>(value: &'a Value) -> Result<T, Fail> {
    T::deserialize(value).map_err(|e| unexpected(&e.to_string()))
}

fn text(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let texts = reply::<TextsReply>(value)?.texts;
    let [text] = texts.as_slice() else {
        return Err(unexpected("not exactly one text"));
    };
    // Not a line: the text is the output, as it was given, down to its last byte.
    out.write_all(text.as_bytes())?;
    Ok(())
}

fn spans(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let spans = reply::<SpansReply>(value)?
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
    writeln!(out, "{} found", plural(len(&spans), "value"))?;
    Ok(())
}

fn files(value: &Value, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Fail> {
    let files = reply::<FilesReply>(value)?.files;
    // The files that hold something, the one with the most first.
    let mut holding: Vec<&FileReply> = files.iter().filter(|file| file.hits() > 0).collect();
    holding.sort_by(|a, b| b.hits().cmp(&a.hits()).then_with(|| a.path.cmp(&b.path)));
    if !holding.is_empty() {
        let rows: Vec<Vec<String>> = holding
            .iter()
            .map(|file| {
                vec![
                    file.hits().to_string(),
                    counts(&file.counts),
                    file.path.clone(),
                ]
            })
            .collect();
        table(out, &["HITS", "FOUND", "FILE"], &[0], &rows)?;
    }
    let hits: u64 = holding.iter().map(|file| file.hits()).sum();
    let failed = files.iter().filter(|file| file.status == "failed").count();
    let skipped = files
        .iter()
        .filter(|file| file.status != "failed" && file.status != "ok")
        .count();
    let mut summary = vec![format!("{} scanned", plural(len(&files), "file"))];
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
    if failed > 0 {
        summary.push(format!("{failed} failed"));
    }
    writeln!(out, "{}", summary.join(", "))?;
    // What went wrong comes after the table even when both end up on the same screen.
    out.flush()?;
    for file in files.iter().filter(|file| file.status == "failed") {
        let why = file.error.as_deref().unwrap_or("could not be read");
        writeln!(err, "piikey-cli: {}: {why}", file.path)?;
    }
    Ok(())
}

fn unexpected(what: &str) -> Fail {
    Fail::Api(ApiError::internal(format!("unexpected reply: {what}")))
}

fn written(value: &Value, out: &mut dyn Write, err: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<WrittenReply>(value)?;
    for moved in &reply.written {
        writeln!(out, "{} -> {}", moved.input, moved.output)?;
    }
    writeln!(
        out,
        "{} written{}",
        plural(len(&reply.written), "file"),
        if reply.failed.is_empty() {
            String::new()
        } else {
            format!(", {} failed", len(&reply.failed))
        }
    )?;
    out.flush()?;
    for failed in &reply.failed {
        writeln!(err, "piikey-cli: {}: {}", failed.input, failed.error)?;
    }
    Ok(())
}

fn subject(values: &[String], value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let matches = reply::<SubjectReply>(value)?.matches;
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
            vec![m.count.to_string(), named.join(", "), m.path.clone()]
        })
        .collect();
    table(out, &["COUNT", "VALUES", "FILE"], &[0], &rows)?;
    let mentioning = len(&matches);
    let verb = if mentioning == 1 {
        "mentions"
    } else {
        "mention"
    };
    writeln!(out, "{} {verb} them", plural(mentioning, "file"))?;
    Ok(())
}

fn records(offset: usize, value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<RecordsReply>(value)?;
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
        let total = u64::try_from(total).unwrap_or(u64::MAX);
        writeln!(out, "{}", plural(total, noun))
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
    match reply::<ForgottenReply>(value)?.forgotten {
        0 => writeln!(out, "no records removed")?,
        n => writeln!(out, "forgot {}", plural(n, "record"))?,
    }
    Ok(())
}

fn exported(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<ExportedReply>(value)?;
    writeln!(
        out,
        "wrote {} to {}",
        plural(reply.records, "record"),
        reply.path
    )?;
    Ok(())
}

fn report(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<ReportReply>(value)?;
    writeln!(out, "wrote {} to {}", plural(reply.rows, "row"), reply.path)?;
    Ok(())
}

fn inventory_status(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<InventoryStatusReply>(value)?;
    let folders = if reply.roots.is_empty() {
        "none".to_owned()
    } else {
        reply.roots.join(", ")
    };
    let scan = reply.scanning.map_or_else(
        || "not running".to_owned(),
        |s| format!("running, {} of {} files", s.done, s.total),
    );
    pairs(
        out,
        &[
            ("inventory", on_off(reply.enabled).to_owned()),
            ("folders", folders),
            ("files", reply.files.to_string()),
            ("with personal data", reply.files_with_pii.to_string()),
            ("values found", reply.hits.to_string()),
            ("scan", scan),
        ],
    )?;
    Ok(())
}

fn entries(offset: usize, value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let reply = reply::<EntriesReply>(value)?;
    if reply.entries.is_empty() {
        writeln!(out, "no files with personal data in the inventory")?;
        return Ok(());
    }
    let rows: Vec<Vec<String>> = reply
        .entries
        .iter()
        .map(|e| vec![e.hits().to_string(), counts(&e.counts), e.path.clone()])
        .collect();
    table(out, &["HITS", "FOUND", "FILE"], &[0], &rows)?;
    footer(out, offset, reply.entries.len(), reply.total, "file")?;
    Ok(())
}

fn nodes(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let nodes = reply::<NodesReply>(value)?.nodes;
    if nodes.is_empty() {
        writeln!(out, "nothing with personal data here")?;
        return Ok(());
    }
    let rows: Vec<Vec<String>> = nodes
        .iter()
        .map(|node| {
            // The node for scans outside every watched folder has no path.
            let place = if node.path.is_empty() {
                node.name.clone()
            } else if node.is_dir {
                format!("{}\\", node.path.trim_end_matches('\\'))
            } else {
                node.path.clone()
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
    let totals = reply::<TotalsReply>(value)?;
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
    let settings = reply::<SettingsReply>(value)?;
    writeln!(out, "highlight={}", settings.highlight)?;
    writeln!(out, "explorer_menu={}", settings.explorer_menu)?;
    writeln!(out, "inventory={}", settings.inventory)?;
    writeln!(out, "http_api={}", settings.http_api)?;
    writeln!(out, "http_port={}", settings.http_port)?;
    let lists = [
        ("site", &settings.sites),
        ("program", &settings.programs),
        ("disabled_kind", &settings.disabled_kinds),
        ("inventory_root", &settings.inventory_roots),
        ("inventory_exclude", &settings.inventory_exclude),
    ];
    for (key, list) in lists {
        for item in list {
            writeln!(out, "{key}={item}")?;
        }
    }
    Ok(())
}

fn kinds(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let kinds = reply::<Vec<KindReply>>(value)?;
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
    let model = reply::<ModelReply>(value)?;
    pairs(
        out,
        &[
            ("model", model_phrase(&model)),
            ("folder", model.dir.clone()),
        ],
    )?;
    Ok(())
}

fn model_phrase(model: &ModelReply) -> String {
    const MB: u64 = 1024 * 1024;
    if let Some(download) = &model.downloading {
        return format!(
            "downloading, {} of {} MB",
            download.done / MB,
            download.total / MB
        );
    }
    match (model.state.as_str(), &model.device, &model.error) {
        ("missing", ..) => "not downloaded (piikey-cli model download)".to_owned(),
        ("unloaded", ..) => "downloaded, loads when it is needed".to_owned(),
        ("ready", Some(device), _) => format!("ready ({device})"),
        ("failed", _, Some(error)) => format!("failed: {error}"),
        (state, ..) => state.to_owned(),
    }
}

/// Just the token, so `$(piikey-cli token)` is the token.
fn token(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    writeln!(out, "{}", reply::<TokenReply>(value)?.token)?;
    Ok(())
}

fn status(value: &Value, out: &mut dyn Write) -> Result<(), Fail> {
    let status = reply::<StatusReply>(value)?;
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
            ("highlight", status.highlight.clone()),
            (
                "explorer menu",
                on_off(status.features.explorer_menu).to_owned(),
            ),
            ("inventory", on_off(status.features.inventory).to_owned()),
            ("HTTP API", on_off(status.features.http_api).to_owned()),
        ],
    )?;
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

fn len<T>(items: &[T]) -> u64 {
    u64::try_from(items.len()).unwrap_or(u64::MAX)
}

/// `email: 3, phone_number: 1`: the kind with the most first.
fn counts(counts: &BTreeMap<String, u64>) -> String {
    let mut sorted: Vec<(&String, &u64)> = counts.iter().filter(|(_, n)| **n > 0).collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
    let parts: Vec<String> = sorted
        .iter()
        .map(|(kind, n)| format!("{kind}: {n}"))
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
