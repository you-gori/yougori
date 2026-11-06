//! The copy of a setup's template package kept beside its project
//! (`<setups>/projects/<setup-id>/package/`), so a sandbox's `files:` can be copied in and the
//! setup can be planned again from exactly the files it was made from. Every path follows the
//! Hub's own rules (`hub::scan::check_path`: relative, no `..`, no reserved or hidden characters),
//! and the copy is written into a fresh folder and swapped in whole.
use std::{
    fs,
    io::ErrorKind,
    path::{Component, Path, PathBuf},
};
use yougori_setup::format::Files;

/// Writes `files` as the package copy at `root`, replacing any copy there.
pub(crate) fn write(root: &Path, files: &Files) -> Result<(), String> {
    let parent = root.parent().ok_or("The setup's folder is missing.")?;
    fs::create_dir_all(parent).map_err(|error| format!("Yougori could not prepare the setup's folder: {error}"))?;
    let metadata = fs::symlink_metadata(parent).map_err(|error| error.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("The setup's folder is not a regular folder, so its template files were not kept.".into());
    }
    let staging = parent.join(format!("package.{}", uuid::Uuid::new_v4().simple()));
    let result = (|| {
        fs::create_dir(&staging).map_err(|error| error.to_string())?;
        for (path, bytes) in files {
            yougori_cli::hub::scan::check_path(path)?;
            let target = path.split('/').fold(staging.clone(), |folder, part| folder.join(part));
            if let Some(folder) = target.parent() {
                fs::create_dir_all(folder).map_err(|error| error.to_string())?;
            }
            fs::write(&target, bytes).map_err(|error| error.to_string())?;
        }
        Ok::<(), String>(())
    })();
    if let Err(error) = result {
        let _ = fs::remove_dir_all(&staging);
        return Err(format!("Yougori could not keep the template's files for this setup: {error}"));
    }
    let retired = parent.join(format!("package.old.{}", uuid::Uuid::new_v4().simple()));
    match fs::rename(root, &retired) {
        Ok(()) => {}
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(format!("Yougori could not replace the setup's earlier template files: {error}"));
        }
    }
    if let Err(error) = fs::rename(&staging, root) {
        let _ = fs::rename(&retired, root);
        let _ = fs::remove_dir_all(&staging);
        return Err(format!("Yougori could not keep the template's files for this setup: {error}"));
    }
    let _ = fs::remove_dir_all(&retired);
    Ok(())
}

/// The package copy at `root`, read with the Hub's collection rules, when there is one.
pub(crate) fn read(root: &Path) -> Option<Files> {
    root.is_dir().then(|| yougori_cli::hub::scan::collect(root).ok().map(|collected| collected.files)).flatten()
}

/// The absolute path of `source`, a path inside the package, refusing anything that leaves it.
pub(crate) fn resolve(root: &Path, source: &str) -> Result<PathBuf, String> {
    let relative = source.trim().trim_start_matches("./");
    let path = Path::new(relative);
    if relative.is_empty() || path.is_absolute() || path.components().any(|part| !matches!(part, Component::Normal(_))) {
        return Err(format!("{source} is not a path inside the template."));
    }
    Ok(path.components().fold(root.to_owned(), |folder, part| folder.join(part)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_package_copy_is_written_whole_read_back_and_replaced() {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path().join("setup-1").join("package");
        let files = Files::from([("yougori-template.yaml".to_owned(), b"one".to_vec()), ("app/server.js".to_owned(), b"two".to_vec())]);
        write(&root, &files).unwrap();
        assert_eq!(read(&root).unwrap(), files);
        let newer = Files::from([("yougori-template.yaml".to_owned(), b"three".to_vec())]);
        write(&root, &newer).unwrap();
        assert_eq!(read(&root).unwrap(), newer, "the old copy is gone, not merged");
        let leftovers = fs::read_dir(folder.path().join("setup-1")).unwrap().count();
        assert_eq!(leftovers, 1, "no staging folder is left behind");
    }

    #[test]
    fn unsafe_paths_never_reach_the_disk() {
        let folder = tempfile::tempdir().unwrap();
        let root = folder.path().join("setup-1").join("package");
        let files = Files::from([("../outside.txt".to_owned(), b"x".to_vec())]);
        assert!(write(&root, &files).is_err());
        assert!(!folder.path().join("setup-1").join("outside.txt").exists());
        assert!(!root.exists());
        assert!(resolve(&root, "../etc").is_err());
        assert!(resolve(&root, "/etc").is_err());
        assert_eq!(resolve(&root, "./app").unwrap(), root.join("app"));
    }
}
