use std::path::PathBuf;

use directories::ProjectDirs;

const QUALIFIER: &str = "";
const ORG: &str = "";
const APP: &str = "tocken";

#[derive(Debug, Clone)]
pub struct StorePaths {
    pub data_dir: PathBuf,
    pub config_dir: PathBuf,
    pub master: PathBuf,
    pub store: PathBuf,
    // TODO(#17): write recipient strings here on every encrypt for
    // human inspection (ADR-100 §4 audit aid). Redundant with the
    // store.age header so not load-bearing.
    #[allow(dead_code)]
    pub recipients: PathBuf,
    // TODO(#3, #8): user-visible config (UX/behavior).
    #[allow(dead_code)]
    pub config: PathBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error("could not determine XDG directories (no HOME?)")]
    NoHome,
}

impl StorePaths {
    pub fn resolve() -> Result<Self, PathError> {
        let dirs = ProjectDirs::from(QUALIFIER, ORG, APP).ok_or(PathError::NoHome)?;
        let data_dir = dirs.data_dir().to_path_buf();
        let config_dir = dirs.config_dir().to_path_buf();
        Ok(Self::from_dirs(data_dir, config_dir))
    }

    pub fn from_dirs(data_dir: PathBuf, config_dir: PathBuf) -> Self {
        Self {
            master: data_dir.join("master.age"),
            store: data_dir.join("store.age"),
            recipients: data_dir.join("recipients.txt"),
            config: config_dir.join("config.toml"),
            data_dir,
            config_dir,
        }
    }

    pub fn ensure_dirs(&self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.data_dir)?;
        std::fs::create_dir_all(&self.config_dir)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_dirs_lays_out_files_under_provided_roots() {
        let paths = StorePaths::from_dirs(
            PathBuf::from("/tmp/data"),
            PathBuf::from("/tmp/config"),
        );
        assert_eq!(paths.master, PathBuf::from("/tmp/data/master.age"));
        assert_eq!(paths.store, PathBuf::from("/tmp/data/store.age"));
        assert_eq!(paths.recipients, PathBuf::from("/tmp/data/recipients.txt"));
        assert_eq!(paths.config, PathBuf::from("/tmp/config/config.toml"));
    }
}
