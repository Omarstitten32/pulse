//! Error type for platform operations.

use std::fmt;
use std::io;

#[derive(Debug)]
pub enum PlatformError {
    Unsupported(&'static str),
    Io { path: String, source: io::Error },
    Parse { path: String, reason: String },
}

impl PlatformError {
    pub fn unsupported(what: &'static str) -> Self {
        Self::Unsupported(what)
    }
    pub fn io(path: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            source,
        }
    }
    pub fn parse(path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::Parse {
            path: path.into(),
            reason: reason.into(),
        }
    }
}

impl fmt::Display for PlatformError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported(what) => write!(f, "unsupported on this platform: {what}"),
            Self::Io { path, source } => write!(f, "i/o error reading {path}: {source}"),
            Self::Parse { path, reason } => write!(f, "parse error in {path}: {reason}"),
        }
    }
}

impl std::error::Error for PlatformError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, PlatformError>;
