//! Crate-wide error type.

use std::fmt;

use crate::detect::EntityKind;

/// Why a piikey operation failed.
#[derive(Debug)]
pub enum Error {
    /// File or pipe I/O failed.
    Io(std::io::Error),
    /// DPAPI refused to wrap or unwrap the vault key (wrong user/machine).
    Dpapi(String),
    /// A vault record other than the last failed authentication.
    VaultCorrupt { record: u64 },
    /// `%LOCALAPPDATA%` is not set, so there is no data folder and no default vault path.
    VaultPathUnavailable,
    /// No unused proxy was found for a value of this kind.
    ProxyExhausted { kind: EntityKind },
    /// The input is in a format piikey cannot process.
    UnsupportedFormat(&'static str),
    /// Reading or writing a zip container failed.
    Zip(String),
    /// Parsing XML failed.
    Xml(String),
    /// Parsing a PDF failed.
    Pdf(String),
    /// Windows OCR or PDF rendering failed.
    Ocr(String),
    /// Parsing an email failed.
    Mail(String),
    /// A named-pipe client sent a malformed request.
    Protocol(&'static str),
    /// The detection model is missing or failed to load or run.
    Model(String),
    /// A System32 tool (`curl.exe`, `certutil.exe`, `reg.exe`) was missing, could not be started
    /// or could not be watched. The message is complete and fit for the user.
    Tool(String),
    /// What this needs is in use by another piikey process (an inventory scan, the API pipe).
    /// The message is complete and fit for the user.
    Busy(String),
    /// A request asked for something that cannot be done: an unknown kind, a setting out of
    /// range, a missing confirmation. The message says what is wrong.
    BadRequest(String),
    /// A lock was poisoned by a panicking thread.
    Poisoned,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "i/o: {e}"),
            Self::Dpapi(e) => write!(f, "dpapi: {e}"),
            Self::VaultCorrupt { record } => write!(f, "vault record {record} is corrupt"),
            Self::VaultPathUnavailable => f.write_str("LOCALAPPDATA is not set; pass --vault PATH"),
            Self::ProxyExhausted { kind } => {
                write!(f, "no unused proxy left for {}", kind.as_str())
            }
            Self::UnsupportedFormat(what) => write!(f, "unsupported format: {what}"),
            Self::Zip(e) => write!(f, "zip: {e}"),
            Self::Xml(e) => write!(f, "xml: {e}"),
            Self::Pdf(e) => write!(f, "pdf: {e}"),
            Self::Ocr(e) => write!(f, "ocr: {e}"),
            Self::Mail(e) => write!(f, "mail: {e}"),
            Self::Protocol(e) => write!(f, "protocol: {e}"),
            Self::Model(e) => write!(f, "detection model: {e}"),
            Self::Tool(e) | Self::Busy(e) | Self::BadRequest(e) => f.write_str(e),
            Self::Poisoned => f.write_str("internal lock poisoned"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<zip::result::ZipError> for Error {
    fn from(e: zip::result::ZipError) -> Self {
        Self::Zip(e.to_string())
    }
}

impl From<quick_xml::Error> for Error {
    fn from(e: quick_xml::Error) -> Self {
        Self::Xml(e.to_string())
    }
}

impl From<lopdf::Error> for Error {
    fn from(e: lopdf::Error) -> Self {
        Self::Pdf(e.to_string())
    }
}

impl From<windows::core::Error> for Error {
    fn from(e: windows::core::Error) -> Self {
        Self::Ocr(e.to_string())
    }
}

impl<T> From<std::sync::PoisonError<T>> for Error {
    fn from(_: std::sync::PoisonError<T>) -> Self {
        Self::Poisoned
    }
}

/// Result alias for piikey operations.
pub type Result<T, E = Error> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::Error;

    #[test]
    fn tool_busy_and_bad_request_show_their_message_as_it_is() {
        for make in [Error::Tool, Error::Busy, Error::BadRequest] {
            let message = "a complete sentence for the user";
            assert_eq!(make(message.to_owned()).to_string(), message);
        }
    }
}
