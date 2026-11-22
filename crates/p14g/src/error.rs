//! The error type returned by every fallible p14g operation.

use std::{error::Error as StdError, fmt, result};

/// Broad category of an [`Error`], stable enough to match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The SQL could not be parsed, or was not exactly one statement.
    Parse,
    /// The SQL is valid but uses syntax p14g cannot represent, so it is rejected.
    Unsupported,
    /// The SQL is understood but the policy does not allow it.
    Denied,
    /// The SQL exceeds one of the configured [`Limits`](crate::Limits).
    Limit,
    /// The policy itself is invalid.
    Config,
    /// A user supplied callback (an insert `extra` or a `filter`) failed or returned something invalid.
    Callback,
}

impl ErrorKind {
    /// Lower case name, used by the Python bindings.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parse => "parse",
            Self::Unsupported => "unsupported",
            Self::Denied => "denied",
            Self::Limit => "limit",
            Self::Config => "config",
            Self::Callback => "callback",
        }
    }
}

/// Position in the input SQL, both 1-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    pub line: u64,
    pub column: u64,
}

/// Why a statement was rejected, or why a policy could not be built.
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
    location: Option<Location>,
    source: Option<Box<dyn StdError + Send + Sync>>,
}

impl Error {
    pub(crate) fn new(kind: ErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            location: None,
            source: None,
        }
    }

    pub(crate) fn unsupported(what: impl fmt::Display) -> Self {
        Self::new(ErrorKind::Unsupported, format!("{what} is not supported"))
    }

    pub(crate) fn denied(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Denied, message)
    }

    pub(crate) fn config(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Config, message)
    }

    pub(crate) fn limit(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Limit, message)
    }

    /// Build an error to return from an `extra` or `filter` callback.
    pub fn callback(message: impl Into<String>) -> Self {
        Self::new(ErrorKind::Callback, message)
    }

    /// Build a callback error that wraps the error which caused it.
    pub fn callback_source(source: impl Into<Box<dyn StdError + Send + Sync>>) -> Self {
        let source = source.into();
        Self {
            kind: ErrorKind::Callback,
            message: format!("callback failed: {source}"),
            location: None,
            source: Some(source),
        }
    }

    pub(crate) fn at(mut self, location: Option<Location>) -> Self {
        if self.location.is_none() {
            self.location = location;
        }
        self
    }

    #[must_use]
    pub fn kind(&self) -> ErrorKind {
        self.kind
    }

    /// The message without the location suffix.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Where in the input the problem was found, when known.
    #[must_use]
    pub fn location(&self) -> Option<Location> {
        self.location
    }

    /// Take the wrapped error out of a callback error.
    pub fn take_source(&mut self) -> Option<Box<dyn StdError + Send + Sync>> {
        self.source.take()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)?;
        if let Some(Location { line, column }) = self.location {
            write!(f, " at line {line}, column {column}")?;
        }
        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_deref().map(|e| e as &(dyn StdError + 'static))
    }
}

pub type Result<T, E = Error> = result::Result<T, E>;
