use super::*;
use std::collections::{BTreeMap, BTreeSet};

impl Live {
    fn folder_filter(&self, two_way: bool) -> Result<sync::Filter, String> {
        let filter = sync::Filter::load(&self.folder, self.env_files)?;
        Ok(if two_way { filter.two_way() } else { filter })
    }

    pub(super) fn find_folder_conflicts(&mut self, local: &std::collections::BTreeMap<String, String>, remote: &std::collections::BTreeMap<String, String>) -> Result<(), String> {
        self.folder_conflicts.clear();
        let local_dirs = sync::directories(&self.folder, &self.folder_filter(true)?)?;
        for dir in &self.saved.directories {
            if self.is_held(dir) { continue; }
            let (l,r) = (local_dirs.contains(dir), self.remote_directories.contains(dir));
            if l == r { continue; }
            let surviving = if l { local } else { remote };
            let dirs = if l { &local_dirs } else { &self.remote_directories };
            let prefix = format!("{dir}/");
            if surviving.iter().any(|(p,h)| p.starts_with(&prefix) && self.saved.common.get(p) != Some(h))
                || dirs.iter().any(|p| p.starts_with(&prefix) && !self.saved.directories.contains(p)) {
                self.folder_conflicts.insert(dir.clone());
            }
        }
        Ok(())
    }

    pub(super) fn folder_conflict(&self, path: &str) -> bool {
        self.folder_conflicts.iter().any(|p| path == p || path.starts_with(&format!("{p}/")))
    }

    pub(super) async fn sync_folders(&mut self, two_way: bool) -> Result<usize, String> {
        self.sync_folders_direction(two_way, if two_way { sync::Direction::Both } else { sync::Direction::ToContainer }).await
    }

    pub(super) async fn sync_folders_direction(&mut self, two_way: bool, direction: sync::Direction) -> Result<usize, String> {
        let local = sync::directories(&self.folder, &self.folder_filter(two_way)?)?;
        let remote = if two_way { self.remote_directories.clone() } else { self.saved.directories.clone() };
        // On a case-insensitive computer, two spellings of a folder name one folder here.
        // Never create or remove it through the other spelling; file sync explains it.
        let mut spellings: BTreeMap<String, BTreeSet<&String>> = BTreeMap::new();
        if two_way && two_way::CASE_INSENSITIVE {
            for path in local.iter().chain(remote.iter()).chain(self.saved.directories.iter()) {
                spellings.entry(two_way::identity(path)).or_default().insert(path);
            }
        }
        let respelled: BTreeSet<String> = spellings.into_values().filter(|names| names.len() > 1).flatten().cloned().collect();
        let paths: BTreeSet<_> = local.iter().chain(remote.iter()).chain(self.saved.directories.iter()).cloned().collect();
        let mut next = self.saved.directories.clone();
        let mut guest_create = Vec::new();
        let mut guest_remove = Vec::new();
        let mut host_create = Vec::new();
        let mut host_remove = Vec::new();
        for path in paths {
            if two_way && self.is_held(&path) { continue; }
            let (l,r,b) = (local.contains(&path),remote.contains(&path),self.saved.directories.contains(&path));
            if l == r { if l { next.insert(path); } else { next.remove(&path); } continue; }
            if two_way && self.folder_conflict(&path) {
                match self.priority {
                    sync::Priority::Local if direction.sends() => { if l { guest_create.push(path); } else { guest_remove.push(path); } }
                    sync::Priority::Remote if direction.receives() => { if r { host_create.push(path); } else { host_remove.push(path); } }
                    sync::Priority::KeepBoth => self.warn_once(format!("Folder conflict: {} — both versions kept", clean(&path))),
                    _ => {}
                }
                continue;
            }
            if !two_way || r == b {
                if direction.sends() { if l { guest_create.push(path); } else { guest_remove.push(path); } }
            } else if l == b {
                if direction.receives() { if r { host_create.push(path); } else { host_remove.push(path); } }
            }
        }
        let mut changed = 0;
        // Parent creation is recursive; removal is always empty-directory-only.
        // A new file created during sync must never be erased by a stale folder scan.
        host_remove.sort_by_key(|p| std::cmp::Reverse(p.split('/').count()));
        guest_remove.sort_by_key(|p| std::cmp::Reverse(p.split('/').count()));
        for (create, paths) in [(true, host_create), (false, host_remove)] {
            for path in paths {
                if respelled.contains(&path) { continue; }
                let target = match two_way::host_target(&self.folder, &path) {
                    Ok(target) => target,
                    Err(error) => { self.warn_once(format!("Folder sync kept {}: {}", clean(&path), clean(&error))); continue; }
                };
                let result = if create { fs::create_dir_all(target) } else { fs::remove_dir(target) };
                match result {
                    Ok(()) => { if create { next.insert(path); } else { next.remove(&path); } changed += 1; }
                    Err(e) if !create && e.kind() == io::ErrorKind::NotFound => { next.remove(&path); }
                    Err(e) => self.warn_once(format!("Folder sync kept {}: {e}", clean(&path))),
                }
            }
        }
        for (create, paths) in [(true, guest_create), (false, guest_remove)] {
            for batch in paths.chunks(64) {
                let reply = self.receiver.rpc(json!({"op":"directories","create":create,"paths":batch})).await?;
                for path in batch {
                    if let Some(error) = reply["errors"][path].as_str() {
                        self.warn_once(format!("Folder sync kept {}: {}", clean(path), clean(error)));
                    } else { if create { next.insert(path.clone()); } else { next.remove(path); } changed += 1; }
                }
                self.pump().await?;
            }
        }
        if self.saved.directories != next { self.saved.directories = next; self.saved.save(&self.state_path)?; }
        Ok(changed)
    }
}
