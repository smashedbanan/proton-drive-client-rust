use crate::error::{Error, Result};
use std::io::Write;
use std::path::{Path, PathBuf};

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

/// Resolves a potential conflict at `local_path`: if nothing exists there,
/// returns it unchanged, no prompt. Otherwise applies `forced` if given,
/// else prompts interactively (plain stdin/stdout — the same mechanism
/// `login` already uses for its username prompt, `commands/login.rs:12-16`;
/// unlike the password prompt, this needs no masking, so it doesn't use
/// `rpassword`). `Skip` returns `Ok(None)` — not an error, matching
/// upload's own "not a failure" treatment of its create-vs-revision
/// branch. `Replace` removes the existing file before returning the same
/// path. `KeepBoth` returns a sibling path from `available_name`.
pub fn resolve_conflict(local_path: &Path, forced: Option<ConflictChoice>) -> Result<Option<PathBuf>> {
    if !local_path.exists() {
        return Ok(Some(local_path.to_path_buf()));
    }

    let choice = match forced {
        Some(choice) => choice,
        None => prompt_for_choice(local_path)?,
    };

    match choice {
        ConflictChoice::Skip => Ok(None),
        ConflictChoice::Replace => {
            std::fs::remove_file(local_path).map_err(Error::Io)?;
            Ok(Some(local_path.to_path_buf()))
        }
        ConflictChoice::KeepBoth => {
            let parent = local_path.parent().unwrap_or_else(|| Path::new("."));
            let base_name = local_path
                .file_name()
                .and_then(|n| n.to_str())
                .ok_or_else(|| Error::Crypto("local file path has no usable file name".into()))?;
            let name = available_name(parent, base_name)?;
            Ok(Some(parent.join(name)))
        }
    }
}

fn prompt_for_choice(local_path: &Path) -> Result<ConflictChoice> {
    loop {
        print!("{} already exists. [s]kip, [r]eplace, or [k]eep both? ", local_path.display());
        std::io::stdout().flush().map_err(Error::Io)?;
        let mut answer = String::new();
        std::io::stdin().read_line(&mut answer).map_err(Error::Io)?;
        match answer.trim().to_lowercase().as_str() {
            "s" | "skip" => return Ok(ConflictChoice::Skip),
            "r" | "replace" => return Ok(ConflictChoice::Replace),
            "k" | "keep-both" | "keep both" => return Ok(ConflictChoice::KeepBoth),
            _ => println!("Please enter 's', 'r', or 'k'."),
        }
    }
}

#[cfg(test)]
mod resolve_conflict_tests {
    use super::*;
    use std::fs;

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("proton-drive-resolve-test-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn returns_the_path_unchanged_when_nothing_exists_there() {
        let dir = temp_dir("no-conflict");
        let target = dir.join("file.txt");
        let resolved = resolve_conflict(&target, None).unwrap();
        assert_eq!(resolved, Some(target));
    }

    #[test]
    fn forced_skip_returns_none_without_touching_the_file() {
        let dir = temp_dir("forced-skip");
        let target = dir.join("file.txt");
        fs::write(&target, b"original").unwrap();
        let resolved = resolve_conflict(&target, Some(ConflictChoice::Skip)).unwrap();
        assert_eq!(resolved, None);
        assert_eq!(fs::read(&target).unwrap(), b"original");
    }

    #[test]
    fn forced_replace_removes_the_existing_file_and_returns_the_same_path() {
        let dir = temp_dir("forced-replace");
        let target = dir.join("file.txt");
        fs::write(&target, b"original").unwrap();
        let resolved = resolve_conflict(&target, Some(ConflictChoice::Replace)).unwrap();
        assert_eq!(resolved, Some(target.clone()));
        assert!(!target.exists());
    }

    #[test]
    fn forced_keep_both_returns_an_available_sibling_path() {
        let dir = temp_dir("forced-keep-both");
        let target = dir.join("file.txt");
        fs::write(&target, b"original").unwrap();
        let resolved = resolve_conflict(&target, Some(ConflictChoice::KeepBoth)).unwrap();
        assert_eq!(resolved, Some(dir.join("file (1).txt")));
        assert_eq!(fs::read(&target).unwrap(), b"original");
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
