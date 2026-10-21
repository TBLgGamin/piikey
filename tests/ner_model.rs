//! Smoke test of the detection model on the real files.
//!
//! It uses the model the app installed (`%LOCALAPPDATA%\piikey\models`) when it is there, so the
//! disk holds one copy; otherwise it needs the network (about 340 MB, kept in
//! `%TEMP%\piikey-ner-test`) and the
//! `curl.exe` and `certutil` that ship with Windows, so it runs on request only:
//!
//! ```sh
//! cargo test --release --test ner_model -- --ignored --nocapture
//! ```
//!
//! The first load measures the GPU against the CPU and keeps both when the GPU helps.
//! `PIIKEY_NER_DEVICE=cpu` or `=hybrid` skips that and forces a device. Whatever the run writes to
//! `device.cfg` is put back at the end.

use std::{
    error::Error,
    fmt::Write as _,
    fs,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};

use piikey::detect::{
    Detector, EntityKind, KindSet, Mode, NerDetector, Span,
    ner::{Device, NerState, files},
};
use tokenizers::Tokenizer;

type Res<T> = Result<T, Box<dyn Error + Send + Sync>>;

const CONTACT: &str = "Kontakt: Jan Kowalski, tel. 600 123 456, ul. D\u{142}uga 5, 00-238 Warszawa";
const INTRO: &str = "Ik ben Jeroen de Vries en werk bij Acme B.V.";
const HOME: &str = "Mijn naam is Jeroen de Vries, ik woon op Keizersgracht 123, 1015 CJ Amsterdam en heb diabetes.";

/// A count as a float (the counts here are far below `u32::MAX`).
fn count(n: usize) -> f64 {
    f64::from(u32::try_from(n).unwrap_or(u32::MAX))
}

fn system_tool(name: &str) -> PathBuf {
    let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    Path::new(&root).join("System32").join(name)
}

/// The SHA-256 of `path`, as `certutil` prints it (hex, with or without spaces).
fn sha256(path: &Path) -> Res<String> {
    let out = Command::new(system_tool("certutil.exe"))
        .args(["-hashfile"])
        .arg(path)
        .arg("SHA256")
        .output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let hash = text
        .lines()
        .nth(1)
        .ok_or("certutil printed no hash")?
        .replace(' ', "")
        .to_lowercase();
    Ok(hash)
}

/// Downloads and checks whatever of the model is not in `dir` yet, then writes the marker.
fn install(dir: &Path) -> Res<()> {
    if files::is_installed(dir) {
        return Ok(());
    }
    fs::create_dir_all(dir)?;
    for file in &files::FILES {
        let path = dir.join(file.name);
        if fs::metadata(&path).is_ok_and(|meta| meta.len() == file.size) {
            continue;
        }
        println!("downloading {} ({} bytes)", file.name, file.size);
        let part = dir.join(format!("{}.part", file.name));
        let status = Command::new(system_tool("curl.exe"))
            .args([
                "--location",
                "--fail",
                "--silent",
                "--show-error",
                "--retry",
                "3",
                "--continue-at",
                "-",
                "--output",
            ])
            .arg(&part)
            .arg(file.url)
            .status()?;
        if !status.success() {
            return Err(format!("curl failed for {}: {status}", file.name).into());
        }
        fs::rename(&part, &path)?;
        assert_eq!(fs::metadata(&path)?.len(), file.size, "{}", file.name);
    }
    for file in &files::FILES {
        let hash = sha256(&dir.join(file.name))?;
        assert_eq!(hash, file.sha256, "SHA-256 of {}", file.name);
    }
    fs::write(dir.join(files::VERIFIED), b"")?;
    Ok(())
}

/// The working set of this process in MB, from `tasklist`.
fn memory_mb() -> Option<u64> {
    let out = Command::new(system_tool("tasklist.exe"))
        .args([
            "/FI",
            &format!("PID eq {}", std::process::id()),
            "/FO",
            "CSV",
            "/NH",
        ])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    let field = text
        .trim()
        .rsplit("\",\"")
        .next()?
        .trim_matches('"')
        .to_owned();
    let kb: String = field.chars().filter(char::is_ascii_digit).collect();
    Some(kb.parse::<u64>().ok()? / 1024)
}

fn show(text: &str, spans: &[Span]) -> String {
    spans
        .iter()
        .map(|s| format!("{:?}={:?}", s.kind, &text[s.start..s.end]))
        .collect::<Vec<_>>()
        .join(", ")
}

fn texts_of(spans: &[Span], text: &str, kind: EntityKind) -> Vec<String> {
    spans
        .iter()
        .filter(|s| s.kind == kind)
        .map(|s| text[s.start..s.end].to_owned())
        .collect()
}

/// The model folder's `device.cfg`. Whatever a run writes there is put back when this is dropped,
/// so that a test run never changes which device the app uses.
struct DeviceFile {
    path: PathBuf,
    before: Option<Vec<u8>>,
}

impl DeviceFile {
    fn new(dir: &Path) -> Self {
        let path = dir.join(files::DEVICE_FILE);
        let before = fs::read(&path).ok();
        Self { path, before }
    }
}

impl Drop for DeviceFile {
    fn drop(&mut self) {
        let _ = match &self.before {
            Some(bytes) => fs::write(&self.path, bytes),
            None => fs::remove_file(&self.path),
        };
    }
}

/// Loads the model, on the device `PIIKEY_NER_DEVICE` forces (`cpu` or `hybrid`), or else on the
/// one the first load measures to be best.
fn load(ner: &NerDetector, dir: &Path) -> Res<Device> {
    let forced = std::env::var("PIIKEY_NER_DEVICE").ok();
    let path = dir.join(files::DEVICE_FILE);
    match &forced {
        Some(device) => fs::write(&path, device)?,
        None => {
            let _ = fs::remove_file(&path);
        }
    }
    let before = memory_mb();
    let start = Instant::now();
    let device = ner.load()?;
    let chosen = fs::read_to_string(&path).ok();
    println!(
        "load: {:?} on {device:?} (device.cfg: {chosen:?}, forced: {forced:?}); memory {before:?} MB -> {:?} MB",
        start.elapsed(),
        memory_mb(),
    );
    assert_eq!(ner.state(), NerState::Ready(device));
    if forced.is_none() {
        let word = match device {
            Device::Hybrid => "hybrid",
            Device::Cpu => "cpu",
        };
        assert_eq!(
            chosen.as_deref(),
            Some(word),
            "the choice is written for the next load"
        );
    }
    Ok(device)
}

/// The Polish contact line from the model card: a name, a phone number and one address.
fn contact_line(ner: &NerDetector) -> Res<()> {
    let contact = ner.detect(CONTACT, Mode::Anonymize);
    println!("{CONTACT}\n  -> {}", show(CONTACT, &contact));
    assert_eq!(
        texts_of(&contact, CONTACT, EntityKind::Person),
        ["Jan Kowalski"]
    );
    let address = "ul. D\u{142}uga 5, 00-238 Warszawa";
    let at = CONTACT.find(address).ok_or("address not in text")?;
    let range = at..at + address.len();
    let addresses: Vec<&Span> = contact
        .iter()
        .filter(|s| s.kind == EntityKind::PostalAddress)
        .collect();
    // Whether `ul.` joins the rest depends on the last digits of the model's output.
    assert!(
        !addresses.is_empty(),
        "no address in {}",
        show(CONTACT, &contact)
    );
    for span in &addresses {
        assert!(
            span.start >= range.start && span.end <= range.end,
            "{:?} is outside the address",
            &CONTACT[span.start..span.end]
        );
    }
    Ok(())
}

/// Dutch, with an organization and the line of the plan's command-line check.
fn dutch_lines(ner: &NerDetector) {
    let intro = ner.detect(INTRO, Mode::Anonymize);
    println!("{INTRO}\n  -> {}", show(INTRO, &intro));
    assert_eq!(
        texts_of(&intro, INTRO, EntityKind::Person),
        ["Jeroen de Vries"]
    );
    let orgs = texts_of(&intro, INTRO, EntityKind::OrganizationName);
    // The decoder trims the final dot off a word, so the span may end before `.`.
    assert!(
        orgs.iter()
            .any(|org| org.starts_with("Acme") && "Acme B.V.".starts_with(org.as_str())),
        "organizations: {orgs:?}"
    );

    let home = ner.detect(HOME, Mode::Anonymize);
    println!("{HOME}\n  -> {}", show(HOME, &home));
    assert_eq!(
        texts_of(&home, HOME, EntityKind::Person),
        ["Jeroen de Vries"]
    );
    assert!(
        !texts_of(&home, HOME, EntityKind::PostalAddress).is_empty(),
        "an address in {}",
        show(HOME, &home)
    );
    // The model does not tag `diabetes` in running text (the reference decoder does not either),
    // so what it makes of health data is only printed.
    println!(
        "health data: {:?}",
        texts_of(&home, HOME, EntityKind::HealthData)
    );
}

/// `wanted` and `taken` are honoured, and Deanonymize never touches the model.
fn caller_filters(ner: &NerDetector) -> Res<()> {
    let only_people = KindSet::EMPTY.with(EntityKind::Person);
    let narrowed = ner.detect_batch(&[HOME], Mode::Anonymize, only_people, &[]);
    assert!(
        narrowed[0].iter().all(|s| s.kind == EntityKind::Person),
        "{narrowed:?}"
    );
    assert!(!narrowed[0].is_empty());
    let name_at = HOME.find("Jeroen").ok_or("name not in text")?;
    let claimed = vec![Span {
        start: name_at,
        end: name_at + 6,
        kind: EntityKind::Email,
    }];
    let rest = ner.detect_batch(&[HOME], Mode::Anonymize, KindSet::ALL, &[claimed]);
    assert!(
        rest[0]
            .iter()
            .all(|s| s.end <= name_at || s.start >= name_at + 6),
        "a span overlaps the claimed one: {}",
        show(HOME, &rest[0])
    );
    assert!(ner.detect(HOME, Mode::Deanonymize).is_empty());
    Ok(())
}

/// Other languages and kinds, printed for the eye.
fn other_languages(ner: &NerDetector) {
    for text in [
        "Hello, my name is Sarah Connor and I live at 1428 Elm Street, Springfield. Call 555-123-4567.",
        "Guten Tag, ich bin Hans M\u{fc}ller aus M\u{fc}nchen, meine Steuernummer ist 12/345/67890.",
        "Pacjent Piotr Nowak, PESEL 44051401359, choruje na astm\u{119}.",
        "I was diagnosed with HIV last year and I am a member of the Labour Party.",
        "Send the invoice to Globex Corporation, VAT NL123456789B01, IBAN NL91 ABNA 0417 1643 00.",
        "The weather in Amsterdam is nice today and the assistant model is gpt-4o.",
    ] {
        let spans = ner.detect(text, Mode::Anonymize);
        println!("{text}\n  -> {}", show(text, &spans));
    }
}

/// 200 copies of the three sentences, each different, so none comes from the cache or is
/// deduplicated; `tag` is what differs between two batches.
fn batch(tag: &str) -> Vec<String> {
    (0..200)
        .flat_map(|i| [CONTACT, INTRO, HOME].map(|s| format!("{s} {tag} {i}.")))
        .collect()
}

/// Time per 1k tokens of one `detect_batch` call over `texts`; asserts every text has a finding.
fn timed_batch(
    ner: &NerDetector,
    tokenizer: &Tokenizer,
    texts: &[String],
    pass: &str,
) -> Res<Vec<Vec<Span>>> {
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let mut tokens = 0;
    for text in texts {
        tokens += tokenizer.encode(text.as_str(), false)?.len();
    }
    let start = Instant::now();
    let found = ner.detect_batch(&refs, Mode::Anonymize, KindSet::ALL, &[]);
    let time = start.elapsed();
    println!(
        "{pass} batch of {} texts, {tokens} tokens: {time:?} = {:.1} ms per 1k tokens",
        refs.len(),
        time.as_secs_f64() * 1000.0 / (count(tokens) / 1000.0),
    );
    assert!(
        found.iter().all(|spans| !spans.is_empty()),
        "every text has something in it"
    );
    Ok(found)
}

/// Calls of growing size, each of different texts: where a call is big enough for the GPU to pay
/// off shows as the time per text dropping.
fn ladder(ner: &NerDetector) {
    for (i, n) in [10, 20, 40, 60, 80, 100, 150, 200, 300]
        .into_iter()
        .enumerate()
    {
        let texts = batch(&format!("Ladder{i}"));
        let refs: Vec<&str> = texts[..n].iter().map(String::as_str).collect();
        let start = Instant::now();
        ner.detect_batch(&refs, Mode::Anonymize, KindSet::ALL, &[]);
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        println!(
            "ladder: {n:>4} texts: {ms:>7.1} ms = {:.2} ms per text",
            ms / count(n)
        );
    }
}

/// One long text: the sentences over and over, each line different, as a document that the
/// model has to cut into windows. 350 lines are about 20k tokens, some 50 windows.
fn document(tag: &str, lines: usize) -> String {
    let mut text = String::new();
    for i in 0..lines {
        let _ = write!(text, "{CONTACT} {tag} {i}. {INTRO}. ");
    }
    text
}

/// Throughput of the loaded model on calls of every size, what the cache does, and what freeing
/// the model gives back.
fn throughput(ner: &NerDetector, dir: &Path, device: Device) -> Res<()> {
    let tokenizer = Tokenizer::from_file(dir.join(files::TOKENIZER_FILE))?;
    let (first, second) = (batch("Kenmerk"), batch("Dossier"));
    ner.release();
    assert_eq!(ner.state(), NerState::Unloaded);
    println!("released: memory {:?} MB", memory_mb());
    let start = Instant::now();
    ner.load()?;
    println!(
        "reload: {:?} on {device:?}; memory {:?} MB",
        start.elapsed(),
        memory_mb()
    );

    // One text at a time, the way a chat message arrives.
    for round in ["Telefoon", "Dossier"] {
        let singles: Vec<String> = (0..20).map(|i| format!("{INTRO} {round} {i}.")).collect();
        let start = Instant::now();
        for text in &singles {
            ner.detect(text, Mode::Anonymize);
        }
        println!(
            "{} single texts ({round}): {:.1} ms each",
            singles.len(),
            start.elapsed().as_secs_f64() * 1000.0 / count(singles.len())
        );
    }
    // A few messages at once: far under what the GPU is started for.
    timed_batch(ner, &tokenizer, &batch("Medium")[..40], "medium")?;
    ladder(ner);
    // Documents of 1k to 8k tokens: two to sixteen windows of 512 positions.
    for (i, lines) in [20, 40, 80, 160].into_iter().enumerate() {
        let doc = document(&format!("Memo{i}"), lines);
        timed_batch(ner, &tokenizer, &[doc], &format!("{lines}-line document"))?;
    }
    // 600 texts, twice: the second shows what the first one's warm-up cost.
    let cold = timed_batch(ner, &tokenizer, &first, "600-text")?;
    timed_batch(ner, &tokenizer, &second, "600-text second")?;
    let refs: Vec<&str> = first.iter().map(String::as_str).collect();
    let start = Instant::now();
    let again = ner.detect_batch(&refs, Mode::Anonymize, KindSet::ALL, &[]);
    println!(
        "the first batch again, from the cache: {:?}",
        start.elapsed()
    );
    assert_eq!(again, cold, "the cache returns what the model did");
    // A large call: 2400 different texts. And one long document.
    let large: Vec<String> = ["Groot-a", "Groot-b", "Groot-c", "Groot-d"]
        .into_iter()
        .flat_map(batch)
        .collect();
    timed_batch(ner, &tokenizer, &large, "large")?;
    timed_batch(ner, &tokenizer, &[document("Rapport", 350)], "document")?;
    println!("memory after the big calls {:?} MB", memory_mb());
    ner.release();
    println!("final memory {:?} MB", memory_mb());
    Ok(())
}

/// The same texts on the CPU alone and on both devices: how many get the same spans. The INT8
/// model is not quite the same on both, so this is only printed.
fn compare_devices(ner: &NerDetector, dir: &Path) -> Res<()> {
    let texts = batch("Vergelijk");
    let refs: Vec<&str> = texts.iter().map(String::as_str).collect();
    let mut found = Vec::new();
    for word in ["cpu", "hybrid"] {
        fs::write(dir.join(files::DEVICE_FILE), word)?;
        ner.release();
        let device = ner.load()?;
        let spans = ner.detect_batch(&refs, Mode::Anonymize, KindSet::ALL, &[]);
        println!("compare: {word} loaded as {device:?}");
        found.push(spans);
    }
    let same = found[0]
        .iter()
        .zip(&found[1])
        .filter(|(a, b)| a == b)
        .count();
    println!(
        "compare: {same} of {} texts have the same spans on the CPU alone and on both devices",
        texts.len()
    );
    ner.release();
    Ok(())
}

#[test]
#[ignore = "downloads the model (about 340 MB) and needs the network"]
fn the_model_finds_names_addresses_and_organizations() -> Res<()> {
    let dir = files::default_dir()
        .ok()
        .filter(|dir| files::is_installed(dir))
        .unwrap_or_else(|| std::env::temp_dir().join("piikey-ner-test"));
    install(&dir)?;
    assert!(files::is_installed(&dir));
    // Whatever this run writes to `device.cfg` is put back at the end.
    let _device_file = DeviceFile::new(&dir);

    let ner = NerDetector::new(dir.clone());
    assert_eq!(ner.state(), NerState::Unloaded);
    let device = load(&ner, &dir)?;
    contact_line(&ner)?;
    dutch_lines(&ner);
    caller_filters(&ner)?;
    other_languages(&ner);
    throughput(&ner, &dir, device)?;
    if std::env::var_os("PIIKEY_NER_DEVICE").is_none() {
        compare_devices(&ner, &dir)?;
    }
    Ok(())
}
