//! Per-file extent trees and inclusion proofs (GPU part §3.3 integrity: "encoded
//! digest/proofs"; "Authenticate the manifest and its referenced trees").
//!
//! Each leaf binds an extent's logical offset, true length, decoded content key and its
//! whole encoding (codec format with its version and frame parameters, dictionary,
//! encoded location and encoded digest), so the root is not a payload-only root:
//! changing an offset, codec or codec version changes it even when the decoded bytes are
//! equal. The tree shape and proof algorithm are those of RFC 9162 §2.1, with
//! domain-separated leaf and node hashes.

use crate::foundation::ids::{Digest, DigestBuilder};

use super::digests::{EXTENT_LEAF_DOMAIN, TREE_EMPTY_DOMAIN, TREE_NODE_DOMAIN};
use super::groups::{Extent, ExtentEncoding};

/// The leaf hash of one extent.
pub fn extent_leaf(extent: &Extent) -> Digest {
    let builder = DigestBuilder::new(EXTENT_LEAF_DOMAIN)
        .u64(extent.logical_offset_bytes)
        .u64(extent.true_length_bytes)
        .digest(extent.content_key.digest());
    match extent.encoding {
        ExtentEncoding::Raw => builder.str("raw"),
        ExtentEncoding::Encoded(encoded) => {
            let builder = encoded.format.bind(builder.str("encoded"));
            let builder = match encoded.dictionary {
                None => builder.str("no-dictionary"),
                Some(dictionary) => builder.str("dictionary").digest(&dictionary.digest()),
            };
            builder
                .u64(encoded.location.file.0.into())
                .u64(encoded.location.offset_bytes)
                .u64(encoded.location.length_bytes)
                .digest(&encoded.digest.digest())
        }
    }
    .finish()
}

fn node(left: &Digest, right: &Digest) -> Digest {
    DigestBuilder::new(TREE_NODE_DOMAIN)
        .digest(left)
        .digest(right)
        .finish()
}

/// The largest power of two below `size`; `size` is at least 2.
fn split_point(size: usize) -> usize {
    let mut split = 1;
    while split * 2 < size {
        split *= 2;
    }
    split
}

/// The root over `leaves` in order.
pub fn tree_root(leaves: &[Digest]) -> Digest {
    match leaves {
        [] => DigestBuilder::new(TREE_EMPTY_DOMAIN).finish(),
        [only] => *only,
        _ => match leaves.split_at_checked(split_point(leaves.len())) {
            Some((left, right)) => node(&tree_root(left), &tree_root(right)),
            None => DigestBuilder::new(TREE_EMPTY_DOMAIN).finish(),
        },
    }
}

/// The audit path of leaf `index`, nearest sibling first; empty when out of range.
pub fn inclusion_path(leaves: &[Digest], index: usize) -> Vec<Digest> {
    let mut path = Vec::new();
    collect_path(leaves, index, &mut path);
    path
}

fn collect_path(leaves: &[Digest], index: usize, path: &mut Vec<Digest>) {
    if leaves.len() <= 1 || index >= leaves.len() {
        return;
    }
    let Some((left, right)) = leaves.split_at_checked(split_point(leaves.len())) else {
        return;
    };
    if index < left.len() {
        collect_path(left, index, path);
        path.push(tree_root(right));
    } else {
        collect_path(right, index - left.len(), path);
        path.push(tree_root(left));
    }
}

/// Whether `path` proves `leaf` is leaf `index` of a `size`-leaf tree with `root`
/// (RFC 9162 §2.1.3.2).
pub fn verify_inclusion(
    root: &Digest,
    leaf: &Digest,
    index: u64,
    size: u64,
    path: &[Digest],
) -> bool {
    if index >= size {
        return false;
    }
    let mut position = index;
    let mut last = size - 1;
    let mut hash = *leaf;
    for sibling in path {
        if last == 0 {
            return false;
        }
        if position & 1 == 1 || position == last {
            hash = node(sibling, &hash);
            while position & 1 == 0 && position != 0 {
                position >>= 1;
                last >>= 1;
            }
        } else {
            hash = node(&hash, sibling);
        }
        position >>= 1;
        last >>= 1;
    }
    last == 0 && hash == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn leaves(count: usize) -> Vec<Digest> {
        (0..count)
            .map(|index| digest("yougori/test/leaf/v1", &[&(index as u64).to_be_bytes()]))
            .collect()
    }

    #[test]
    fn every_leaf_of_every_small_tree_proves_and_nothing_else_does() {
        for size in 1..=33usize {
            let leaves = leaves(size);
            let root = tree_root(&leaves);
            for (index, leaf) in leaves.iter().enumerate() {
                let path = inclusion_path(&leaves, index);
                assert!(verify_inclusion(
                    &root,
                    leaf,
                    index as u64,
                    size as u64,
                    &path
                ));
                let other = digest("yougori/test/leaf/v1", &[b"other"]);
                assert!(!verify_inclusion(
                    &root,
                    &other,
                    index as u64,
                    size as u64,
                    &path
                ));
                if size > 1 {
                    let wrong_index = (index + 1) % size;
                    assert!(
                        leaves[wrong_index] == *leaf
                            || !verify_inclusion(
                                &root,
                                leaf,
                                wrong_index as u64,
                                size as u64,
                                &path
                            )
                    );
                    let mut tampered = path.clone();
                    tampered[0] = other;
                    assert!(!verify_inclusion(
                        &root,
                        leaf,
                        index as u64,
                        size as u64,
                        &tampered
                    ));
                }
                assert!(!verify_inclusion(
                    &root,
                    leaf,
                    size as u64,
                    size as u64,
                    &path
                ));
            }
        }
    }

    #[test]
    fn roots_depend_on_order_and_count() {
        let four = leaves(4);
        let mut swapped = four.clone();
        swapped.swap(1, 2);
        assert_ne!(tree_root(&four), tree_root(&swapped));
        assert_ne!(tree_root(&four), tree_root(&four[..3]));
        assert_ne!(tree_root(&[]), tree_root(&four[..1]));
        assert_eq!(tree_root(&four[..1]), four[0]);
    }
}
