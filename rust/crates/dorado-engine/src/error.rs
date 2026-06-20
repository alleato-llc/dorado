//! The engine's error type.
//!
//! A small typed enum so callers can distinguish failure kinds (a malformed or
//! unsupported file, bad parameters, an authentication failure, or underlying I/O)
//! instead of matching on strings. The frontends render errors with `Display`, so a
//! `From<Error> for String` is provided for that convenience.
//!
//! One deliberate non-distinction: a wrong password and a tampered or corrupted file
//! both surface as [`Error::AuthFailed`] with the same message. Telling them apart
//! would leak whether the key was right, so they are merged on purpose.

use std::fmt;

/// An error from the engine: container construction, parsing, or verification.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Authentication failed: a wrong password, or a corrupted or tampered file.
    /// These cases are intentionally indistinguishable.
    AuthFailed,
    /// The container header or a frame is malformed or truncated. The string says
    /// what was being read.
    MalformedHeader(String),
    /// The container's format version is not one this build can read.
    UnsupportedVersion(u8),
    /// A parameter was invalid or out of bounds: a key or tweak length, a chunk
    /// size, a KDF cost, a label length, or malformed hex input. The string says
    /// which.
    InvalidParams(String),
    /// An underlying I/O error from the reader or writer.
    Io(std::io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::AuthFailed => {
                write!(f, "authentication failed: wrong password or corrupted file")
            }
            Error::MalformedHeader(what) => write!(f, "malformed container: {what}"),
            Error::UnsupportedVersion(v) => write!(f, "unsupported container version {v}"),
            Error::InvalidParams(what) => write!(f, "{what}"),
            Error::Io(e) => write!(f, "io error: {e}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

/// The frontends present errors as strings; this lets their `Result<_, String>`
/// code absorb an engine error with `?` or `.into()`.
impl From<Error> for String {
    fn from(e: Error) -> Self {
        e.to_string()
    }
}

/// A `Result` whose error is the engine [`Error`].
pub type Result<T> = std::result::Result<T, Error>;
