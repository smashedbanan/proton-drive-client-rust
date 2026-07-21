use crate::error::Result;
use std::path::Path;

/// How to handle a local-file conflict on download — ported 1:1 from the
/// reference CLI's own three file-conflict strategies
/// (`cli/src/commands/fileSystem/commandFileSystemDownload.ts:30-34`),
/// minus `Merge` (folders only, out of scope — this crate never downloads
/// folders). `#[derive(clap::ValueEnum)]` doubles this enum as both the
/// CLI flag's value type and the resolver's internal choice type, so
/// there's one definition, not two parallel ones.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum ConflictChoice {
    Skip,
    Replace,
    #[value(name = "keep-both")]
    KeepBoth,
}

/// Finds the first available name alongside `base_name` in `parent_dir`:
/// `base_name` itself if nothing collides, else `name (1).ext`,
/// `name (2).ext`, ... in order — mirrors the reference CLI's own
/// `getAvailableLocalName` (`commandFileSystemDownload.ts:352-373`),
/// including its treatment of a leading dot (e.g. `.gitignore`) as having
/// no extension at all (`dot > 0` there, `Some(0) | None` here).
pub fn available_name(parent_dir: &Path, base_name: &str) -> Result<String> {
    if !parent_dir.join(base_name).exists() {
        return Ok(base_name.to_string());
    }
    let (stem, ext) = match base_name.rfind('.') {
        Some(0) | None => (base_name, ""),
        Some(i) => (&base_name[..i], &base_name[i..]),
    };
    let mut i = 1;
    loop {
        let candidate = format!("{stem} ({i}){ext}");
        if !parent_dir.join(&candidate).exists() {
            return Ok(candidate);
        }
        i += 1;
    }
}

#[cfg(test)]
mod available_name_tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("proton-drive-conflict-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn returns_the_base_name_unchanged_when_nothing_collides() {
        let dir = temp_dir("no-collision");
        assert_eq!(available_name(&dir, "file.txt").unwrap(), "file.txt");
    }

    #[test]
    fn appends_a_numeric_suffix_before_the_extension_on_collision() {
        let dir = temp_dir("collision");
        fs::write(dir.join("file.txt"), b"existing").unwrap();
        assert_eq!(available_name(&dir, "file.txt").unwrap(), "file (1).txt");
    }

    #[test]
    fn keeps_incrementing_past_multiple_collisions() {
        let dir = temp_dir("multi-collision");
        fs::write(dir.join("file.txt"), b"existing").unwrap();
        fs::write(dir.join("file (1).txt"), b"existing").unwrap();
        assert_eq!(available_name(&dir, "file.txt").unwrap(), "file (2).txt");
    }

    #[test]
    fn treats_a_leading_dot_as_having_no_extension() {
        let dir = temp_dir("dotfile");
        fs::write(dir.join(".gitignore"), b"existing").unwrap();
        assert_eq!(available_name(&dir, ".gitignore").unwrap(), ".gitignore (1)");
    }
}
