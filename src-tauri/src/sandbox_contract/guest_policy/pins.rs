//! Pinned paths: what keeps a protected path where V15 names it (M07B; VM-CP-05; the M07A
//! review: "the read-only mount on `.git/hooks` can be sidestepped by renaming the
//! workload-owned `.git`, the mount moves with it").
//!
//! A read-only mount and root ownership protect an inode, not a name. When the workload can
//! write the directory holding a protected path, it can rename that path, or a directory
//! between it and its root, and create a writable one in its place: a mount moves with the
//! renamed directory, and a root-owned file in a workload-owned directory can be renamed
//! away. The kernel refuses to rename or remove a mount point of the caller's mount
//! namespace: rename(2) and rmdir(2) fail with `EBUSY`. So under a read-only mount or
//! credential separation [`pinned_paths`] pins each protected path's root (the home or the
//! workspace), every directory between the root and the path, and the path itself when no
//! read-only mount covers it. The installer bind-mounts each pin onto itself, read-write,
//! in the inner container's mount namespace before the workload starts. A pin grants
//! nothing: it changes no permission, owner or mount flag and only makes the name
//! immovable. A path a read-only mount covers is a mount point already and is not pinned.
//! The installer creates a missing pin first (an ancestor as a directory of the workload's
//! uid, a protected path as its `PathKind`), and applies the pins before the read-only
//! mounts, or as recursive binds, so that a pin never hides a read-only mount beneath it;
//! the mount boot check (`super::boot`) shows both in place.
//!
//! Under the LSM alone nothing is pinned. Landlock handles `REFER` and the remove rights,
//! and a protected path and every directory above it lie outside every grant (a grant
//! containing one would contain the protected path, which the grant rule of
//! `super::grants` refuses), so Landlock refuses the rename itself.
//!
//! Removing a pin needs `CAP_SYS_ADMIN`, which no profile may hold (V15 `NEVER_GRANTED`);
//! in a user namespace the workload creates, the copied mounts are locked and still mount
//! points there.

use std::collections::BTreeSet;

use super::compile::GuestPolicyRefusal;
use super::paths::{AbsoluteGuestPath, GuestLayout};
use crate::sandbox_contract::confinement::{Mechanism, PathRoot, ProtectedPath};

/// The paths to pin for `paths` under `layout` when protected-path writes are refused by
/// `mechanisms`, in path order without repeats; empty unless a read-only mount or
/// credential separation is among `mechanisms` (see the module notes).
pub fn pinned_paths(
    paths: &[ProtectedPath],
    layout: &GuestLayout,
    mechanisms: &[Mechanism],
) -> Result<Vec<AbsoluteGuestPath>, GuestPolicyRefusal> {
    let read_only = mechanisms.contains(&Mechanism::ReadOnlyMount);
    if !read_only && !mechanisms.contains(&Mechanism::NamespaceCredentials) {
        return Ok(Vec::new());
    }
    let mut mounted = BTreeSet::new();
    let mut pins = BTreeSet::new();
    for path in paths {
        let unresolvable = |refusal| GuestPolicyRefusal::UnresolvablePath {
            path: path.clone(),
            refusal,
        };
        let guest = layout.resolve(path).map_err(unresolvable)?;
        let root = match path.root() {
            PathRoot::Home => layout.home(),
            PathRoot::Workspace => layout.workspace(),
        };
        let components = guest.components();
        for depth in root.components().len()..components.len() {
            if let Some(prefix) = components.get(..depth) {
                let directory = AbsoluteGuestPath::parse(&format!("/{}", prefix.join("/")))
                    .map_err(unresolvable)?;
                pins.insert(directory);
            }
        }
        if read_only {
            mounted.insert(guest);
        } else {
            pins.insert(guest);
        }
    }
    Ok(pins.difference(&mounted).cloned().collect())
}
