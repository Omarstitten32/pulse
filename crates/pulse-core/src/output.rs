//! Output targets (stdout / file).

use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub enum Target {
    Stdout,
    File(PathBuf),
}

impl Target {
    pub fn from_path<P: AsRef<Path>>(p: P) -> Self {
        Self::File(p.as_ref().to_path_buf())
    }

    pub fn write(&self, content: &str) -> io::Result<()> {
        let needs_trailing_nl = !content.ends_with('\n');
        match self {
            Self::Stdout => {
                let stdout = io::stdout();
                let mut h = stdout.lock();
                h.write_all(content.as_bytes())?;
                if needs_trailing_nl {
                    h.write_all(b"\n")?;
                }
                h.flush()
            }
            Self::File(path) => {
                let mut f = File::create(path)?;
                f.write_all(content.as_bytes())?;
                if needs_trailing_nl {
                    f.write_all(b"\n")?;
                }
                f.flush()
            }
        }
    }

    pub fn path(&self) -> Option<&Path> {
        match self {
            Self::File(p) => Some(p.as_path()),
            Self::Stdout => None,
        }
    }

    pub fn is_file(&self) -> bool {
        matches!(self, Self::File(_))
    }
}
