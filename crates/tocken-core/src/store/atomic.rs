use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;

use tempfile::NamedTempFile;

#[derive(Debug, thiserror::Error)]
pub enum AtomicWriteError {
    #[error("missing parent directory for {0}")]
    NoParent(std::path::PathBuf),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Atomically replace `target` with `bytes`.
///
/// Writes to a sibling temp file, fsyncs the file, renames over the target,
/// then fsyncs the parent directory so the rename itself is durable.
/// On crash, either the old contents or the new contents survive — never a
/// truncated mix.
pub fn write(target: &Path, bytes: &[u8]) -> Result<(), AtomicWriteError> {
    let parent = target
        .parent()
        .ok_or_else(|| AtomicWriteError::NoParent(target.to_path_buf()))?;
    std::fs::create_dir_all(parent)?;

    let mut tmp = NamedTempFile::new_in(parent)?;
    tmp.write_all(bytes)?;
    tmp.as_file_mut().sync_all()?;
    let persisted: File = tmp.persist(target).map_err(|e| e.error)?;
    drop(persisted);

    let dir = OpenOptions::new().read(true).open(parent)?;
    dir.sync_all()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.bin");
        write(&target, b"hello").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"hello");
    }

    #[test]
    fn replaces_existing_file_atomically() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("a.bin");
        std::fs::write(&target, b"original").unwrap();
        write(&target, b"replaced").unwrap();
        assert_eq!(std::fs::read(&target).unwrap(), b"replaced");
    }

    // Crash-during-write coverage is intentionally not unit-tested.
    // The atomic property comes from the OS rename + fsync semantics;
    // exercising it requires killing the process mid-write, which
    // belongs in an out-of-process harness, not here.
}
