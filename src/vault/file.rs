//! The vault file: header, framed AEAD records, and the I/O around them.
//!
//! ```text
//! header: "PKV1" | u32 dpapi_len | dpapi blob | 16-byte vault_id
//! record: u32 ct_len | 24-byte nonce | ciphertext (ct_len bytes, ends in the 16-byte tag)
//! plain : kind u8 | u16 orig_len | orig | u16 proxy_len | proxy
//! aad   : vault_id | u64 record_index
//! ```
//!
//! Integers are little-endian. This is an on-disk format: never reorder or
//! renumber anything here.
//!
//! A crash can only damage the end of the file, so a record that is cut
//! short, zero-filled, or fails authentication is forgiven only when nothing
//! valid follows it. Damage anywhere else is `VaultCorrupt`.

use std::{fs::File, io, ops::Range, os::windows::fs::FileExt, sync::Arc};

use chacha20poly1305::{AeadInOut, XChaCha20Poly1305, XNonce, aead::inout::InOutBuf};
use rayon::prelude::*;

use super::keys::fill_random;
use crate::{Error, Result, detect::EntityKind};

const MAGIC: &[u8; 4] = b"PKV1";
/// `MAGIC` + `u32 dpapi_len` + `vault_id`: the header without the DPAPI blob.
const HEADER_FIXED: u64 = 4 + 4 + 16;
pub(super) const VAULT_ID_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
/// `u32 ct_len` + nonce: what precedes a record's ciphertext.
const FRAME_HEAD: usize = 4 + NONCE_LEN;
/// A wrapped 32-byte key is a few hundred bytes; more is not a vault header.
const MAX_WRAPPED_LEN: u32 = 64 * 1024;
/// Longest original or proxy: its length is a `u16`.
const MAX_VALUE_LEN: usize = 65_535;
/// `kind` plus two empty length-prefixed strings: the smallest plaintext.
const MIN_PLAIN: usize = 1 + 2 + 2;
const MIN_CT: usize = MIN_PLAIN + TAG_LEN;
const MAX_CT: usize = MIN_PLAIN + 2 * MAX_VALUE_LEN + TAG_LEN;

type Id = [u8; VAULT_ID_LEN];

fn invalid(msg: &'static str) -> Error {
    Error::Io(io::Error::new(io::ErrorKind::InvalidData, msg))
}

/// One issued mapping.
pub(super) struct Entry {
    pub(super) kind: EntityKind,
    pub(super) original: Arc<str>,
    pub(super) proxy: Arc<str>,
}

/// Holds the exclusive byte-range lock on the whole file until dropped.
///
/// On Windows the lock is mandatory: other handles, in this process or any
/// other, cannot read or write the file while it is held, so every access
/// beyond the header happens under it.
pub(super) struct FileLock<'a>(&'a File);

impl<'a> FileLock<'a> {
    /// Blocks until no other handle holds a lock.
    pub(super) fn exclusive(file: &'a File) -> io::Result<Self> {
        file.lock()?;
        Ok(Self(file))
    }
}

impl Drop for FileLock<'_> {
    fn drop(&mut self) {
        // Closing the handle releases the lock as well, so a failure is harmless.
        let _ = self.0.unlock();
    }
}

/// Reads exactly `buf.len()` bytes at `offset`, independent of the file cursor.
pub(super) fn read_exact_at(file: &File, mut buf: &mut [u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        match file.seek_read(buf, offset) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(n) => {
                buf = &mut buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Writes all of `buf` at `offset`, independent of the file cursor.
pub(super) fn write_all_at(file: &File, mut buf: &[u8], mut offset: u64) -> io::Result<()> {
    while !buf.is_empty() {
        match file.seek_write(buf, offset) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(n) => {
                buf = &buf[n..];
                offset += n as u64;
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// Reads the bytes `start..end` of the file.
pub(super) fn read_range(file: &File, start: u64, end: u64) -> Result<Vec<u8>> {
    let len = usize::try_from(end - start).map_err(|_| invalid("vault file too large"))?;
    let mut data = vec![0u8; len];
    read_exact_at(file, &mut data, start)?;
    Ok(data)
}

/// A parsed vault header.
pub(super) struct Header {
    /// The DPAPI-wrapped master key.
    pub(super) wrapped_key: Vec<u8>,
    pub(super) vault_id: Id,
    /// Size of the header in bytes; records start here.
    pub(super) len: u64,
}

pub(super) fn encode_header(wrapped_key: &[u8], vault_id: &Id) -> Result<Vec<u8>> {
    let len = u32::try_from(wrapped_key.len())
        .ok()
        .filter(|&len| len <= MAX_WRAPPED_LEN)
        .ok_or_else(|| invalid("wrapped vault key too large"))?;
    let mut out = Vec::with_capacity(wrapped_key.len() + 8 + VAULT_ID_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(wrapped_key);
    out.extend_from_slice(vault_id);
    Ok(out)
}

/// Parses the header of a non-empty file of `file_len` bytes.
pub(super) fn read_header(file: &File, file_len: u64) -> Result<Header> {
    let mut fixed = [0u8; 8];
    if file_len < 8 {
        return Err(invalid("not a piikey vault (file too short)"));
    }
    read_exact_at(file, &mut fixed, 0)?;
    if fixed[..4] != *MAGIC {
        return Err(invalid("not a piikey vault (bad magic)"));
    }
    let wrapped_len = u32::from_le_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]);
    if wrapped_len > MAX_WRAPPED_LEN {
        return Err(invalid("vault header is corrupt (key size)"));
    }
    let len = HEADER_FIXED + u64::from(wrapped_len);
    if file_len < len {
        return Err(invalid("vault header is truncated"));
    }
    let mut wrapped_key = vec![0u8; usize::try_from(wrapped_len).map_err(|_| invalid("key size"))?];
    read_exact_at(file, &mut wrapped_key, 8)?;
    let mut vault_id = [0u8; VAULT_ID_LEN];
    read_exact_at(file, &mut vault_id, 8 + u64::from(wrapped_len))?;
    Ok(Header {
        wrapped_key,
        vault_id,
        len,
    })
}

fn aad(vault_id: &Id, index: u64) -> [u8; VAULT_ID_LEN + 8] {
    let mut aad = [0u8; VAULT_ID_LEN + 8];
    aad[..VAULT_ID_LEN].copy_from_slice(vault_id);
    aad[VAULT_ID_LEN..].copy_from_slice(&index.to_le_bytes());
    aad
}

/// Encrypts `entries` as records `first_index..` and returns their bytes,
/// ready to append.
pub(super) fn seal(
    cipher: &XChaCha20Poly1305,
    vault_id: &Id,
    first_index: u64,
    entries: &[Entry],
) -> Result<Vec<u8>> {
    let capacity = entries
        .iter()
        .map(|e| FRAME_HEAD + MIN_PLAIN + e.original.len() + e.proxy.len() + TAG_LEN)
        .sum();
    let mut out = Vec::with_capacity(capacity);
    for (index, entry) in (first_index..).zip(entries) {
        seal_one(cipher, vault_id, index, entry, &mut out)?;
    }
    Ok(out)
}

fn seal_one(
    cipher: &XChaCha20Poly1305,
    vault_id: &Id,
    index: u64,
    entry: &Entry,
    out: &mut Vec<u8>,
) -> Result<()> {
    let too_long = || invalid("value longer than 65535 bytes");
    let original_len = u16::try_from(entry.original.len()).map_err(|_| too_long())?;
    let proxy_len = u16::try_from(entry.proxy.len()).map_err(|_| too_long())?;
    let plain_len = MIN_PLAIN + entry.original.len() + entry.proxy.len();
    let ct_len = u32::try_from(plain_len + TAG_LEN).map_err(|_| too_long())?;
    let mut nonce = [0u8; NONCE_LEN];
    fill_random(&mut nonce)?;

    out.extend_from_slice(&ct_len.to_le_bytes());
    out.extend_from_slice(&nonce);
    let plain_start = out.len();
    out.push(entry.kind as u8);
    out.extend_from_slice(&original_len.to_le_bytes());
    out.extend_from_slice(entry.original.as_bytes());
    out.extend_from_slice(&proxy_len.to_le_bytes());
    out.extend_from_slice(entry.proxy.as_bytes());
    let tag = cipher
        .encrypt_inout_detached(
            XNonce::cast_from_core(&nonce),
            &aad(vault_id, index),
            InOutBuf::from(&mut out[plain_start..]),
        )
        .map_err(|_| Error::Io(io::Error::other("vault record encryption failed")))?;
    out.extend_from_slice(&tag);
    Ok(())
}

/// Where one complete record sits inside the scanned bytes.
#[derive(Clone, Copy)]
pub(super) struct Frame {
    start: usize,
    ct_len: usize,
}

impl Frame {
    fn nonce(self) -> Range<usize> {
        self.start + 4..self.start + FRAME_HEAD
    }

    fn ciphertext(self) -> Range<usize> {
        self.start + FRAME_HEAD..self.end()
    }

    fn end(self) -> usize {
        self.start + FRAME_HEAD + self.ct_len
    }
}

/// What follows the last complete record.
#[derive(PartialEq, Eq)]
enum Tail {
    /// Nothing: the records end where the data ends.
    Clean,
    /// An unfinished record, or zeros where a crash extended the file.
    Torn,
    /// Bytes that no record could start with.
    Garbage,
}

/// Splits `data` into complete records without decrypting them.
fn scan(data: &[u8]) -> (Vec<Frame>, Tail) {
    let mut frames = Vec::new();
    let mut at = 0;
    while let Some(rest) = data.get(at..).filter(|rest| !rest.is_empty()) {
        if rest.len() < FRAME_HEAD + MIN_CT {
            return (frames, Tail::Torn);
        }
        let len = u32::from_le_bytes([rest[0], rest[1], rest[2], rest[3]]);
        let ct_len = usize::try_from(len).unwrap_or(usize::MAX);
        if !(MIN_CT..=MAX_CT).contains(&ct_len) {
            let tail = if rest.iter().all(|&b| b == 0) {
                Tail::Torn
            } else {
                Tail::Garbage
            };
            return (frames, tail);
        }
        let frame = Frame { start: at, ct_len };
        if frame.end() > data.len() {
            return (frames, Tail::Torn);
        }
        frames.push(frame);
        at = frame.end();
    }
    (frames, Tail::Clean)
}

/// The records of a byte range and where the valid ones end.
pub(super) struct Framed {
    pub(super) frames: Vec<Frame>,
    /// Bytes covered by valid records. Anything after is a torn write.
    pub(super) good_len: usize,
}

/// Finds the records in `data`, whose first record has index `first_index`,
/// and decides where the valid ones end. Only the last record is decrypted
/// (to see whether it is a torn write); [`decrypt`] does the rest.
///
/// # Errors
/// `VaultCorrupt` when unframeable bytes follow the last record.
pub(super) fn frame(
    cipher: &XChaCha20Poly1305,
    vault_id: &Id,
    data: &[u8],
    first_index: u64,
) -> Result<Framed> {
    let (mut frames, tail) = scan(data);
    if tail == Tail::Garbage {
        return Err(Error::VaultCorrupt {
            record: first_index + frames.len() as u64,
        });
    }
    if let Some(&last) = frames.last() {
        let index = first_index + (frames.len() - 1) as u64;
        if open_one(cipher, vault_id, index, data, last, &mut Vec::new()).is_none() {
            frames.pop();
        }
    }
    let good_len = frames.last().map_or(0, |frame| frame.end());
    Ok(Framed { frames, good_len })
}

/// Decrypts `frames` of `data`, whose first record has index `first_index`.
/// `parallel` spreads the work over rayon; callers holding a lock must not
/// ask for it.
///
/// # Errors
/// `VaultCorrupt` with the index of the first record that fails.
pub(super) fn decrypt(
    cipher: &XChaCha20Poly1305,
    vault_id: &Id,
    data: &[u8],
    frames: &[Frame],
    first_index: u64,
    parallel: bool,
) -> Result<Vec<Entry>> {
    let open = |plain: &mut Vec<u8>, (i, &frame): (usize, &Frame)| {
        open_one(cipher, vault_id, first_index + i as u64, data, frame, plain)
    };
    let opened: Vec<Option<Entry>> = if parallel {
        frames
            .par_iter()
            .enumerate()
            .map_init(Vec::new, open)
            .collect()
    } else {
        let mut plain = Vec::new();
        frames
            .iter()
            .enumerate()
            .map(|item| open(&mut plain, item))
            .collect()
    };
    (first_index..)
        .zip(opened)
        .map(|(record, entry)| entry.ok_or(Error::VaultCorrupt { record }))
        .collect()
}

/// Decrypts and parses one record; `None` if it fails authentication or is
/// malformed. `plain` is scratch space.
fn open_one(
    cipher: &XChaCha20Poly1305,
    vault_id: &Id,
    index: u64,
    data: &[u8],
    frame: Frame,
    plain: &mut Vec<u8>,
) -> Option<Entry> {
    let nonce: [u8; NONCE_LEN] = data.get(frame.nonce())?.try_into().ok()?;
    plain.clear();
    plain.extend_from_slice(data.get(frame.ciphertext())?);
    cipher
        .decrypt_in_place(XNonce::cast_from_core(&nonce), &aad(vault_id, index), plain)
        .ok()?;
    let (kind, original, proxy) = parse_plain(plain)?;
    Some(Entry {
        kind,
        original: Arc::from(original),
        proxy: Arc::from(proxy),
    })
}

/// Cursor over a record's plaintext.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let (head, tail) = self.0.split_at_checked(n)?;
        self.0 = tail;
        Some(head)
    }

    fn u16(&mut self) -> Option<u16> {
        let &[lo, hi] = self.take(2)? else {
            return None;
        };
        Some(u16::from_le_bytes([lo, hi]))
    }

    fn string(&mut self) -> Option<&'a str> {
        let len = usize::from(self.u16()?);
        std::str::from_utf8(self.take(len)?).ok()
    }
}

fn parse_plain(plain: &[u8]) -> Option<(EntityKind, &str, &str)> {
    let mut reader = Reader(plain);
    let kind = EntityKind::from_u8(*reader.take(1)?.first()?)?;
    let original = reader.string()?;
    let proxy = reader.string()?;
    reader.0.is_empty().then_some((kind, original, proxy))
}

#[cfg(test)]
mod tests {
    use chacha20poly1305::{Key, KeyInit};

    use super::*;

    const ID: Id = [9; VAULT_ID_LEN];

    fn cipher() -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new(Key::cast_from_core(&[7u8; 32]))
    }

    fn entry(kind: EntityKind, original: &str, proxy: &str) -> Entry {
        Entry {
            kind,
            original: original.into(),
            proxy: proxy.into(),
        }
    }

    fn pairs(entries: &[Entry]) -> Vec<(EntityKind, &str, &str)> {
        entries
            .iter()
            .map(|e| (e.kind, &*e.original, &*e.proxy))
            .collect()
    }

    fn sample() -> Vec<Entry> {
        vec![
            entry(
                EntityKind::Email,
                "jan.jansen@example.org",
                "pieter.bakker@orchardgate.org",
            ),
            entry(
                EntityKind::Iban,
                "NL91 ABNA 0417 1643 00",
                "NL37 ABNA 0912 3304 18",
            ),
            entry(EntityKind::Phone, "+31 6 12345678", "+31 6 70418253"),
        ]
    }

    /// Byte offset of every record in `bytes`, found with the documented layout.
    fn record_starts(bytes: &[u8]) -> Vec<usize> {
        let mut starts = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            starts.push(at);
            let len = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
            at += FRAME_HEAD + usize::try_from(len).unwrap_or(usize::MAX);
        }
        assert_eq!(at, bytes.len());
        starts
    }

    #[test]
    fn records_round_trip_serial_and_parallel() -> Result<()> {
        let entries = sample();
        let bytes = seal(&cipher(), &ID, 5, &entries)?;
        let framed = frame(&cipher(), &ID, &bytes, 5)?;
        assert_eq!(framed.frames.len(), 3);
        assert_eq!(framed.good_len, bytes.len());
        for parallel in [false, true] {
            let opened = decrypt(&cipher(), &ID, &bytes, &framed.frames, 5, parallel)?;
            assert_eq!(pairs(&opened), pairs(&entries));
        }
        Ok(())
    }

    #[test]
    fn layout_matches_the_documented_format() -> Result<()> {
        let bytes = seal(&cipher(), &ID, 0, &sample()[..1])?;
        let plain_len =
            1 + 2 + "jan.jansen@example.org".len() + 2 + "pieter.bakker@orchardgate.org".len();
        let ct_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(usize::try_from(ct_len), Ok(plain_len + 16));
        assert_eq!(bytes.len(), 4 + 24 + plain_len + 16);
        Ok(())
    }

    #[test]
    fn every_record_binds_its_index_and_vault() -> Result<()> {
        let bytes = seal(&cipher(), &ID, 0, &sample())?;
        // Records moved to another position fail authentication.
        assert!(matches!(
            decrypt(
                &cipher(),
                &ID,
                &bytes,
                &frame(&cipher(), &ID, &bytes, 0)?.frames,
                1,
                false
            ),
            Err(Error::VaultCorrupt { record: 1 })
        ));
        // So do records read under another vault id.
        assert!(matches!(
            decrypt(
                &cipher(),
                &[1; VAULT_ID_LEN],
                &bytes,
                &frame(&cipher(), &ID, &bytes, 0)?.frames,
                0,
                false
            ),
            Err(Error::VaultCorrupt { record: 0 })
        ));
        Ok(())
    }

    #[test]
    fn records_use_distinct_nonces() -> Result<()> {
        let one = entry(EntityKind::Mac, "aa:bb:cc:dd:ee:ff", "aa:bb:cc:11:22:33");
        let bytes = seal(&cipher(), &ID, 0, &[one])?;
        let again = seal(
            &cipher(),
            &ID,
            0,
            &[entry(
                EntityKind::Mac,
                "aa:bb:cc:dd:ee:ff",
                "aa:bb:cc:11:22:33",
            )],
        )?;
        assert_ne!(bytes[4..FRAME_HEAD], again[4..FRAME_HEAD]);
        Ok(())
    }

    #[test]
    fn values_up_to_the_u16_limit_round_trip_and_longer_ones_are_rejected() -> Result<()> {
        let big = "x".repeat(MAX_VALUE_LEN + 1);
        let result = seal(&cipher(), &ID, 0, &[entry(EntityKind::Secret, &big, "y")]);
        assert!(matches!(result, Err(Error::Io(_))));
        let result = seal(&cipher(), &ID, 0, &[entry(EntityKind::Secret, "y", &big)]);
        assert!(matches!(result, Err(Error::Io(_))));

        let max = "x".repeat(MAX_VALUE_LEN);
        let entries = [entry(EntityKind::Secret, &max, &max)];
        let bytes = seal(&cipher(), &ID, 0, &entries)?;
        let framed = frame(&cipher(), &ID, &bytes, 0)?;
        assert_eq!(framed.frames.len(), 1);
        let opened = decrypt(&cipher(), &ID, &bytes, &framed.frames, 0, false)?;
        assert_eq!(pairs(&opened), pairs(&entries));
        Ok(())
    }

    #[test]
    fn empty_data_has_no_records() -> Result<()> {
        let framed = frame(&cipher(), &ID, &[], 0)?;
        assert!(framed.frames.is_empty());
        assert_eq!(framed.good_len, 0);
        Ok(())
    }

    #[test]
    fn short_garbage_after_the_records_is_a_torn_write() -> Result<()> {
        let mut bytes = seal(&cipher(), &ID, 0, &sample())?;
        let good = bytes.len();
        bytes.extend_from_slice(&[0xAB; 10]);
        let framed = frame(&cipher(), &ID, &bytes, 0)?;
        assert_eq!(framed.frames.len(), 3);
        assert_eq!(framed.good_len, good);
        Ok(())
    }

    #[test]
    fn a_record_cut_short_is_a_torn_write() -> Result<()> {
        let bytes = seal(&cipher(), &ID, 0, &sample())?;
        let starts = record_starts(&bytes);
        for cut in [starts[2] + 2, starts[2] + 30, bytes.len() - 1] {
            let framed = frame(&cipher(), &ID, &bytes[..cut], 0)?;
            assert_eq!(framed.frames.len(), 2, "cut at {cut}");
            assert_eq!(framed.good_len, starts[2]);
        }
        Ok(())
    }

    #[test]
    fn zeros_after_the_records_are_a_torn_write() -> Result<()> {
        let mut bytes = seal(&cipher(), &ID, 0, &sample())?;
        let good = bytes.len();
        bytes.extend_from_slice(&[0; 4096]);
        let framed = frame(&cipher(), &ID, &bytes, 0)?;
        assert_eq!(framed.frames.len(), 3);
        assert_eq!(framed.good_len, good);
        Ok(())
    }

    #[test]
    fn unframeable_bytes_after_the_records_are_corruption() -> Result<()> {
        let mut bytes = seal(&cipher(), &ID, 0, &sample())?;
        bytes.extend_from_slice(&[0xFF; 200]);
        assert!(matches!(
            frame(&cipher(), &ID, &bytes, 0),
            Err(Error::VaultCorrupt { record: 3 })
        ));
        Ok(())
    }

    #[test]
    fn a_failing_last_record_is_dropped() -> Result<()> {
        let mut bytes = seal(&cipher(), &ID, 0, &sample())?;
        let starts = record_starts(&bytes);
        bytes[starts[2] + FRAME_HEAD + 3] ^= 1;
        let framed = frame(&cipher(), &ID, &bytes, 0)?;
        assert_eq!(framed.frames.len(), 2);
        assert_eq!(framed.good_len, starts[2]);
        Ok(())
    }

    #[test]
    fn a_failing_last_record_followed_by_a_cut_record_is_dropped_too() -> Result<()> {
        let mut bytes = seal(&cipher(), &ID, 0, &sample())?;
        let starts = record_starts(&bytes);
        bytes[starts[1] + FRAME_HEAD + 3] ^= 1;
        bytes.truncate(starts[2] + 10);
        let framed = frame(&cipher(), &ID, &bytes, 0)?;
        assert_eq!(framed.frames.len(), 1);
        assert_eq!(framed.good_len, starts[1]);
        Ok(())
    }

    #[test]
    fn a_failing_middle_record_is_corruption() -> Result<()> {
        let mut bytes = seal(&cipher(), &ID, 0, &sample())?;
        let starts = record_starts(&bytes);
        bytes[starts[1] + FRAME_HEAD + 3] ^= 1;
        let framed = frame(&cipher(), &ID, &bytes, 0)?;
        assert_eq!(framed.frames.len(), 3);
        for parallel in [false, true] {
            assert!(matches!(
                decrypt(&cipher(), &ID, &bytes, &framed.frames, 0, parallel),
                Err(Error::VaultCorrupt { record: 1 })
            ));
        }
        Ok(())
    }

    #[test]
    fn plaintext_must_be_exact() {
        let ok = [3, 1, 0, b'a', 1, 0, b'b'];
        assert_eq!(parse_plain(&ok), Some((EntityKind::Email, "a", "b")));
        assert_eq!(
            parse_plain(&[3, 1, 0, b'a', 1, 0, b'b', 0]),
            None,
            "trailing byte"
        );
        assert_eq!(
            parse_plain(&[3, 1, 0, b'a', 2, 0, b'b']),
            None,
            "short proxy"
        );
        assert_eq!(parse_plain(&[0, 1, 0, b'a', 1, 0, b'b']), None, "kind 0");
        assert_eq!(
            parse_plain(&[12, 1, 0, b'a', 1, 0, b'b']),
            None,
            "unknown kind"
        );
        assert_eq!(
            parse_plain(&[3, 1, 0, 0xFF, 1, 0, b'b']),
            None,
            "invalid UTF-8"
        );
        assert_eq!(parse_plain(&[]), None);
    }

    #[test]
    fn header_round_trips_and_rejects_damage() -> Result<()> {
        let dir = std::env::temp_dir().join(format!("piikey-test-{}-header", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let path = dir.join("h.pkv");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(&path)?;
        let blob = vec![0x5A; 300];
        let header = encode_header(&blob, &ID)?;
        write_all_at(&file, &header, 0)?;
        let len = file.metadata()?.len();
        let parsed = read_header(&file, len)?;
        assert_eq!(parsed.wrapped_key, blob);
        assert_eq!(parsed.vault_id, ID);
        assert_eq!(parsed.len, len);

        write_all_at(&file, b"PKV2", 0)?;
        assert!(matches!(read_header(&file, len), Err(Error::Io(_))));
        write_all_at(&file, b"PKV1", 0)?;
        assert!(matches!(read_header(&file, len - 1), Err(Error::Io(_))));
        write_all_at(&file, &u32::MAX.to_le_bytes(), 4)?;
        assert!(matches!(read_header(&file, len), Err(Error::Io(_))));
        drop(file);
        std::fs::remove_dir_all(&dir)?;
        Ok(())
    }
}
