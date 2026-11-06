//! OCI symlinks resolve inside the consuming VM's chroot. V05's host-file archive
//! checks deliberately refuse absolute targets; adapt only their validation view
//! here, never the image's stored target or the host-file policy. Extraction writes
//! directories and files before symlinks, and nothing follows these links on the host.
use crate::sandbox_contract::files::{
    check_archive_for, ArchiveEntry, ArchiveEntryKind, ArchiveLimits,
    ImageArchiveRefusal as ArchiveRefusal, ImageName,
};
use std::collections::{BTreeMap, VecDeque};

// Resolve each component before processing the next `..`, as the guest kernel does.
// This is a virtual image namespace; it never opens a host path. Cycles, excessive
// work and attempts to climb above the image root fail closed.
fn image_target(name: &ImageName, target: &str, links: &BTreeMap<&str, &str>) -> Option<String> {
    fn prepend(
        target: &str,
        stack: &mut Vec<String>,
        pending: &mut VecDeque<String>,
    ) -> Option<()> {
        if target.is_empty()
            || target.len() > 4096
            || target.contains('\\')
            || target.starts_with("//")
        {
            return None;
        }
        let text = if let Some(text) = target.strip_prefix('/') {
            stack.clear();
            text
        } else {
            target
        };
        let parts: Vec<_> = text.split('/').collect();
        if pending.len().checked_add(parts.len())? > 1024 {
            return None;
        }
        for part in parts.into_iter().rev() {
            if part.is_empty() {
                return None;
            }
            pending.push_front(part.to_owned());
        }
        Some(())
    }
    let mut stack = name
        .parent()
        .map(|parent| parent.components().map(str::to_owned).collect())
        .unwrap_or_default();
    let mut pending = VecDeque::new();
    prepend(target, &mut stack, &mut pending)?;
    let mut hops = 0;
    let mut steps = 0;
    while let Some(part) = pending.pop_front() {
        steps += 1;
        if steps > 4096 {
            return None;
        }
        match part.as_str() {
            "." => {}
            ".." => {
                stack.pop()?;
            }
            _ => {
                stack.push(part);
                let path = stack.join("/");
                ImageName::parse(&path).ok()?;
                if let Some(next) = links.get(path.as_str()) {
                    hops += 1;
                    if hops > 40 {
                        return None;
                    }
                    stack.pop();
                    prepend(next, &mut stack, &mut pending)?;
                }
            }
        }
    }
    let path = stack.join("/");
    ImageName::parse(&path).ok()?;
    Some(path)
}

pub(super) fn check_image_archive(
    entries: &[ArchiveEntry],
    limits: &ArchiveLimits,
) -> Result<(), ArchiveRefusal> {
    if entries.len() > limits.max_entries {
        return Err(ArchiveRefusal::TooManyEntries {
            entries: entries.len(),
            limit: limits.max_entries,
        });
    }
    let links: BTreeMap<_, _> = entries
        .iter()
        .filter_map(|entry| match &entry.kind {
            ArchiveEntryKind::Symlink { target } => Some((entry.name.as_str(), target.as_str())),
            _ => None,
        })
        .collect();
    let mut checked = entries.to_vec();
    for (index, entry) in checked.iter_mut().enumerate() {
        if let ArchiveEntryKind::Symlink { target } = &mut entry.kind {
            let name = ImageName::parse(&entry.name)
                .map_err(|refusal| ArchiveRefusal::UnsafeName { index, refusal })?;
            let resolved = image_target(&name, target, &links).ok_or_else(|| {
                ArchiveRefusal::EscapingLink {
                    index,
                    name: name.clone(),
                }
            })?;
            let parents = name
                .parent()
                .map_or(0, |parent| parent.components().count());
            *target = format!("{}{resolved}", "../".repeat(parents));
        }
    }
    // Reuse the limits, collision, device, hard-link and write-through-link checks
    // with resolved targets. Stored symlink strings are never rewritten.
    check_archive_for::<true>(&checked, limits).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::super::ImportLimits;
    use super::*;
    use crate::sandbox_contract::files::check_archive;

    fn link(name: &str, target: &str) -> ArchiveEntry {
        ArchiveEntry {
            name: name.into(),
            kind: ArchiveEntryKind::Symlink {
                target: target.into(),
            },
        }
    }

    #[test]
    fn image_names_are_linux_exact_and_cannot_enter_the_host_file_namespace() {
        use crate::sandbox_contract::files::GuestName;
        let names = [
            "Doc",
            "doc",
            "lib/x:y",
            "café",
            "cafe\u{301}",
            "NUL.txt",
            "trail. ",
            "a~1",
        ];
        let entries: Vec<_> = names
            .iter()
            .map(|name| ArchiveEntry {
                name: (*name).into(),
                kind: ArchiveEntryKind::File {
                    compressed_bytes: 1,
                    uncompressed_bytes: 1,
                },
            })
            .collect();
        let limits = ImportLimits::default().tree_archive_limits();
        check_image_archive(&entries, &limits).unwrap();
        assert!(check_archive(&entries, &limits).is_err());
        for name in &names[2..] {
            assert!(GuestName::parse(name).is_err());
        }
        let mut duplicate = entries.clone();
        duplicate.push(entries[0].clone());
        assert!(check_image_archive(&duplicate, &limits).is_err());
        for name in [
            "../escape",
            "/etc/passwd",
            "a\\b",
            "a//b",
            "a/./b",
            "a\0b",
            "a\u{85}b",
        ] {
            assert!(ImageName::parse(name).is_err(), "{name:?}");
        }
        assert!(check_image_archive(&[link("link", "/lib/x:y")], &limits).is_ok());
        assert!(check_archive(&[link("link", "/lib/x:y")], &limits).is_err());
    }

    #[test]
    fn absolute_image_links_remain_literal_and_host_archives_still_refuse_them() {
        let entries = vec![
            ArchiveEntry {
                name: "bin".into(),
                kind: ArchiveEntryKind::Directory,
            },
            ArchiveEntry {
                name: "bin/busybox".into(),
                kind: ArchiveEntryKind::File {
                    compressed_bytes: 1,
                    uncompressed_bytes: 1,
                },
            },
            link("bin/arch", "/bin/busybox"),
        ];
        let limits = ImportLimits::default().tree_archive_limits();
        assert!(matches!(
            check_archive(&entries, &limits),
            Err(crate::sandbox_contract::files::ArchiveRefusal::EscapingLink { .. })
        ));
        check_image_archive(&entries, &limits).unwrap();
        assert_eq!(entries[2], link("bin/arch", "/bin/busybox"));
    }

    #[test]
    fn rebasing_does_not_allow_root_escape_cycles_or_writes_through_links() {
        let limits = ImportLimits::default().tree_archive_limits();
        for target in ["/../../outside", "//host/share", "/etc\\passwd"] {
            assert!(
                check_image_archive(&[link("nested/link", target)], &limits).is_err(),
                "{target}"
            );
        }
        assert!(
            check_image_archive(&[link("alias", "/other"), link("other", "/alias")], &limits)
                .is_err()
        );
        let through = [
            link("alias", "/real"),
            ArchiveEntry {
                name: "alias/file".into(),
                kind: ArchiveEntryKind::File {
                    compressed_bytes: 1,
                    uncompressed_bytes: 1,
                },
            },
        ];
        assert!(check_image_archive(&through, &limits).is_err());
    }

    #[test]
    fn contained_chains_work_but_host_archives_still_refuse_them() {
        let limits = ImportLimits::default().tree_archive_limits();
        let links = [link("alias", "real"), link("other", "alias")];
        check_image_archive(&links, &limits).unwrap();
        assert!(matches!(
            check_image_archive(
                &links,
                &ArchiveLimits {
                    max_entries: 1,
                    ..limits
                }
            ),
            Err(ArchiveRefusal::TooManyEntries {
                entries: 2,
                limit: 1
            })
        ));
        assert!(matches!(
            check_archive(&links, &limits),
            Err(crate::sandbox_contract::files::ArchiveRefusal::ThroughLink { .. })
        ));
        // Resolve a directory link before `..`: lexical normalization alone would
        // miss this escape above the virtual root.
        let links = [
            link("nested/dir", "/real"),
            link("jump", "nested/dir/../../outside"),
        ];
        assert!(check_image_archive(&links, &limits).is_err());
        let too_deep: Vec<_> = (0..42)
            .map(|i| link(&format!("n{i}"), &format!("n{}", i + 1)))
            .collect();
        assert!(check_image_archive(&too_deep, &limits).is_err());
    }
}
