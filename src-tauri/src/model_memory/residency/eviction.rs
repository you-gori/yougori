//! Clean eviction (GPU §1.1, line 307): drop a clean GPU copy without copying it back
//! only when a verified reconstructible copy exists; dirty or unverified state is written
//! back or retained.
//!
//! A copy is reconstructible only when it is verified to hold exactly the GPU copy's
//! content and sits in a tier that guarantees it stays available: pinned host RAM held by
//! the runtime, or local storage (§3.4). An unverified copy never counts. Reclaimable host
//! RAM may vanish (§2.7: reclaimability is not guaranteed residency), and a peer's or a
//! remote source's authorization and availability can expire (§3.4), so those copies do
//! not count either, however well verified.
//!
//! Graph pools are the exception the plan's tier table makes (§3.4: graph resources are
//! GPU-tier content with no copy in any other tier): a clean pool is dropped for
//! recapture over its resident weights node, with no device-to-host copy, and a dirty
//! pool is retained because nothing can take it back.

use serde::Serialize;

use crate::foundation::ids::{ContentKey, Digest};

/// What a set of bytes holds: the identity verification compares (line 307).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Content {
    /// Immutable content, such as base weights or an adapter, named by the key of its
    /// bytes (GPU §3.3).
    Immutable(ContentKey),
    /// One state of mutable session KV, named by a marker digest that changes with every
    /// request. It names a state, not hashed bytes, so it is not a [`ContentKey`] and never
    /// equals one.
    SessionState(Digest),
    /// A graph pool captured over the weights `weights` names, under the runtime
    /// configuration `execution_key` names (§1.1, line 309: an execution key, not an
    /// address, validates graph reuse). It names what a recapture reproduces, not hashed
    /// bytes: equal bytes in another role are another object, so it never equals the
    /// weights' own content key or a session state, and no tier outside the GPU holds it
    /// (§3.4).
    GraphPool {
        weights: ContentKey,
        execution_key: Digest,
    },
}

impl Content {
    /// Whether this is a graph pool, which is captured again rather than copied.
    pub const fn is_graph_pool(&self) -> bool {
        matches!(self, Self::GraphPool { .. })
    }
}

/// Whether the GPU bytes still equal the content they were loaded or written back as.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum ContentState {
    /// Unchanged since it was loaded or last written back.
    Clean,
    /// Changed since, such as KV that grew during a request; no other copy holds it.
    Dirty,
}

/// One GPU copy that eviction would free.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct GpuCopy {
    /// The content the bytes hold while clean.
    pub content: Content,
    pub state: ContentState,
    pub bytes: u64,
}

/// Where another copy lives: the storage tiers of §3.4 other than the GPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum CopyTier {
    /// Pinned host RAM held by the runtime under its hard cap.
    PinnedHost,
    /// Page cache or an ordinary host copy, which may be reclaimed at any time.
    ReclaimableHost,
    /// A local storage artifact.
    LocalStorage,
    /// An authorized peer's copy, behind an expiring authorization and a donor budget.
    AuthorizedPeer,
    /// The original or publisher-prepared remote source.
    RemoteSource,
}

impl CopyTier {
    /// Whether a copy here stays available until it is needed again: only pinned host
    /// RAM held by the runtime and local storage (§2.7, §3.4).
    pub const fn guarantees_availability(self) -> bool {
        matches!(self, Self::PinnedHost | Self::LocalStorage)
    }

    /// Lower is the faster source to reconstruct from.
    const fn preference(self) -> u8 {
        match self {
            Self::PinnedHost => 0,
            Self::LocalStorage => 1,
            Self::ReclaimableHost => 2,
            Self::AuthorizedPeer => 3,
            Self::RemoteSource => 4,
        }
    }
}

/// What is known about a copy's content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum Verification {
    /// The copy was checked to hold `content`: its bytes hash to the content key, or it
    /// captured that session state.
    Verified { content: Content },
    /// Never checked, or the check failed: never reconstructible.
    Unverified,
}

/// Another copy of an object, outside the GPU.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ReconstructibleCopy {
    pub tier: CopyTier,
    pub verification: Verification,
}

impl ReconstructibleCopy {
    /// Whether this copy can rebuild `content` exactly once the GPU copy is gone: verified
    /// for that content and in a tier that guarantees availability (line 307). No tier
    /// holds graph resources (§3.4), so nothing reconstructs a graph pool.
    pub fn reconstructs(&self, content: &Content) -> bool {
        if content.is_graph_pool() {
            return false;
        }
        let verified = match self.verification {
            Verification::Verified { content: verified } => verified == *content,
            Verification::Unverified => false,
        };
        verified && self.tier.guarantees_availability()
    }
}

/// Whether the runtime can copy GPU bytes back to a verified copy now.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum WriteBack {
    Available,
    Unavailable,
}

/// Why a GPU copy cannot simply be dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum NotDroppable {
    /// The bytes changed since any copy was made.
    Dirty,
    /// No copy is verified for this content in a tier that guarantees availability.
    NoVerifiedCopy,
}

/// What evicting a GPU copy takes (GPU §1.1, line 307).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum EvictionAction {
    /// Free the GPU bytes with no device-to-host copy; `source` rebuilds them.
    DropClean { source: CopyTier },
    /// Free a graph pool's GPU bytes with no device-to-host copy; a capture over its
    /// resident weights node rebuilds them. No tier outside the GPU holds graph
    /// resources (§3.4), so copies play no part.
    Recapture,
    /// Copy the bytes back to a verified copy first, then free them.
    WriteBackThenDrop {
        d2h_bytes: u64,
        because: NotDroppable,
    },
    /// Keep the GPU copy: freeing it now would lose state.
    Retain { because: NotDroppable },
}

impl EvictionAction {
    /// Device-to-host bytes the action moves.
    pub const fn d2h_bytes(&self) -> u64 {
        match self {
            Self::WriteBackThenDrop { d2h_bytes, .. } => *d2h_bytes,
            Self::DropClean { .. } | Self::Recapture | Self::Retain { .. } => 0,
        }
    }
}

/// Decides how a GPU copy may be evicted (GPU §1.1, line 307).
///
/// A clean copy is dropped only when some copy [`reconstructs`](ReconstructibleCopy::reconstructs)
/// its content; the fastest such tier is reported. Dirty or unverified state is written
/// back when that is available and retained otherwise; it is never dropped.
///
/// A graph pool holds no copy and takes no write-back (§3.4): clean, it is dropped for
/// recapture; dirty, it no longer matches its capture key and is retained.
pub fn eviction_action(
    gpu: &GpuCopy,
    copies: &[ReconstructibleCopy],
    write_back: WriteBack,
) -> EvictionAction {
    if gpu.content.is_graph_pool() {
        return match gpu.state {
            ContentState::Clean => EvictionAction::Recapture,
            ContentState::Dirty => EvictionAction::Retain {
                because: NotDroppable::Dirty,
            },
        };
    }
    let because = match gpu.state {
        ContentState::Dirty => NotDroppable::Dirty,
        ContentState::Clean => {
            let source = copies
                .iter()
                .filter(|copy| copy.reconstructs(&gpu.content))
                .map(|copy| copy.tier)
                .min_by_key(|tier| tier.preference());
            match source {
                Some(source) => return EvictionAction::DropClean { source },
                None => NotDroppable::NoVerifiedCopy,
            }
        }
    };
    match write_back {
        WriteBack::Available => EvictionAction::WriteBackThenDrop {
            d2h_bytes: gpu.bytes,
            because,
        },
        WriteBack::Unavailable => EvictionAction::Retain { because },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    const SESSION: &str = "yougori/test/residency/session/v1";

    fn weights(bytes: &[u8]) -> Content {
        Content::Immutable(ContentKey::of(bytes))
    }

    fn copy(tier: CopyTier, verification: Verification) -> ReconstructibleCopy {
        ReconstructibleCopy { tier, verification }
    }

    fn clean(content: Content) -> GpuCopy {
        GpuCopy {
            content,
            state: ContentState::Clean,
            bytes: 14_000,
        }
    }

    #[test]
    fn a_clean_copy_is_dropped_only_with_a_verified_reconstructible_copy() {
        let content = weights(b"model-a");
        let verified = Verification::Verified { content };
        assert_eq!(
            eviction_action(
                &clean(content),
                &[copy(CopyTier::LocalStorage, verified)],
                WriteBack::Available
            ),
            EvictionAction::DropClean {
                source: CopyTier::LocalStorage
            }
        );
        // Without any copy, or with only an unverified one, the bytes are written back.
        for copies in [
            Vec::new(),
            vec![copy(CopyTier::LocalStorage, Verification::Unverified)],
            vec![copy(CopyTier::PinnedHost, Verification::Unverified)],
        ] {
            assert_eq!(
                eviction_action(&clean(content), &copies, WriteBack::Available),
                EvictionAction::WriteBackThenDrop {
                    d2h_bytes: 14_000,
                    because: NotDroppable::NoVerifiedCopy
                }
            );
        }
    }

    #[test]
    fn a_verified_copy_of_other_content_does_not_count() {
        let content = weights(b"model-a");
        let older = Verification::Verified {
            content: weights(b"model-a-previous-revision"),
        };
        assert_eq!(
            eviction_action(
                &clean(content),
                &[copy(CopyTier::LocalStorage, older)],
                WriteBack::Unavailable
            ),
            EvictionAction::Retain {
                because: NotDroppable::NoVerifiedCopy
            }
        );
    }

    #[test]
    fn only_tiers_that_guarantee_availability_reconstruct() {
        let content = weights(b"model-a");
        let verified = Verification::Verified { content };
        for tier in [
            CopyTier::ReclaimableHost,
            CopyTier::AuthorizedPeer,
            CopyTier::RemoteSource,
        ] {
            assert!(!tier.guarantees_availability());
            assert!(!copy(tier, verified).reconstructs(&content));
            assert_eq!(
                eviction_action(
                    &clean(content),
                    &[copy(tier, verified)],
                    WriteBack::Available
                )
                .d2h_bytes(),
                14_000
            );
        }
        for tier in [CopyTier::PinnedHost, CopyTier::LocalStorage] {
            assert!(copy(tier, verified).reconstructs(&content));
        }
    }

    #[test]
    fn the_fastest_reconstructible_tier_is_the_source() {
        let content = weights(b"model-a");
        let verified = Verification::Verified { content };
        let action = eviction_action(
            &clean(content),
            &[
                copy(CopyTier::RemoteSource, verified),
                copy(CopyTier::LocalStorage, verified),
                copy(CopyTier::PinnedHost, verified),
            ],
            WriteBack::Available,
        );
        assert_eq!(
            action,
            EvictionAction::DropClean {
                source: CopyTier::PinnedHost
            }
        );
        assert_eq!(action.d2h_bytes(), 0);
    }

    #[test]
    fn dirty_state_is_written_back_or_retained_never_dropped() {
        let content = Content::SessionState(digest(SESSION, &[b"session-kv"]));
        let dirty = GpuCopy {
            content,
            state: ContentState::Dirty,
            bytes: 512,
        };
        // Even a verified copy of the same digest does not make dirty bytes droppable.
        let copies = [copy(
            CopyTier::PinnedHost,
            Verification::Verified { content },
        )];
        assert_eq!(
            eviction_action(&dirty, &copies, WriteBack::Available),
            EvictionAction::WriteBackThenDrop {
                d2h_bytes: 512,
                because: NotDroppable::Dirty
            }
        );
        assert_eq!(
            eviction_action(&dirty, &copies, WriteBack::Unavailable),
            EvictionAction::Retain {
                because: NotDroppable::Dirty
            }
        );
        // Once written back, the clean state drops against its verified copy.
        assert_eq!(
            eviction_action(
                &GpuCopy {
                    state: ContentState::Clean,
                    ..dirty
                },
                &copies,
                WriteBack::Unavailable
            ),
            EvictionAction::DropClean {
                source: CopyTier::PinnedHost
            }
        );
    }

    fn pool(weights: &[u8], execution_key: &[u8]) -> Content {
        Content::GraphPool {
            weights: ContentKey::of(weights),
            execution_key: digest("yougori/test/residency/execution-key/v1", &[execution_key]),
        }
    }

    #[test]
    fn a_clean_graph_pool_is_dropped_for_recapture_with_no_copy_and_no_write_back() {
        let content = pool(b"model-a", b"bs1-8");
        let gpu = GpuCopy {
            content,
            state: ContentState::Clean,
            bytes: 300,
        };
        // No copy, with or without a write-back path: recaptured, no device-to-host bytes.
        for write_back in [WriteBack::Available, WriteBack::Unavailable] {
            let action = eviction_action(&gpu, &[], write_back);
            assert_eq!(action, EvictionAction::Recapture);
            assert_eq!(action.d2h_bytes(), 0);
        }
        assert!(content.is_graph_pool());
        assert!(!Content::Immutable(ContentKey::of(b"model-a")).is_graph_pool());
    }

    #[test]
    fn nothing_reconstructs_a_graph_pool_and_a_dirty_pool_is_retained() {
        let content = pool(b"model-a", b"bs1-8");
        // A copy claiming the pool's own content, even verified in pinned host RAM, holds
        // no graph resources (§3.4); one of the weights it was captured over is other
        // content.
        let claims = [
            copy(CopyTier::PinnedHost, Verification::Verified { content }),
            copy(CopyTier::LocalStorage, Verification::Verified { content }),
            copy(
                CopyTier::LocalStorage,
                Verification::Verified {
                    content: weights(b"model-a"),
                },
            ),
        ];
        for claim in &claims {
            assert!(!claim.reconstructs(&content));
        }
        assert_eq!(
            eviction_action(&clean(content), &claims, WriteBack::Unavailable),
            EvictionAction::Recapture
        );
        // Dirty bytes no longer match the capture key and cannot be written back anywhere.
        let dirty = GpuCopy {
            content,
            state: ContentState::Dirty,
            bytes: 300,
        };
        for write_back in [WriteBack::Available, WriteBack::Unavailable] {
            assert_eq!(
                eviction_action(&dirty, &claims, write_back),
                EvictionAction::Retain {
                    because: NotDroppable::Dirty
                }
            );
        }
    }

    #[test]
    fn a_graph_pool_never_equals_the_weights_it_was_captured_over() {
        let weights_key = ContentKey::of(b"model-a");
        let as_weights = Content::Immutable(weights_key);
        let as_pool = Content::GraphPool {
            weights: weights_key,
            execution_key: *weights_key.digest(),
        };
        let as_state = Content::SessionState(*weights_key.digest());
        assert_ne!(as_pool, as_weights);
        assert_ne!(as_pool, as_state);
        // The weights' verified copy drops the weights, not the pool.
        let weights_copy = copy(
            CopyTier::LocalStorage,
            Verification::Verified {
                content: as_weights,
            },
        );
        assert!(weights_copy.reconstructs(&as_weights));
        assert!(!weights_copy.reconstructs(&as_pool));
        // Two pools over the same weights under different configurations differ.
        assert_ne!(as_pool, pool(b"model-a", b"other configuration"));
    }

    #[test]
    fn a_session_state_never_matches_a_content_key() {
        // The same 32 bytes as a content key and as a session-state marker.
        let bytes = *ContentKey::of(b"model-a").digest();
        let as_state = Content::SessionState(bytes);
        let as_content = Content::Immutable(ContentKey::from_digest(bytes));
        assert_ne!(as_state, as_content);
        let state_copy = copy(
            CopyTier::LocalStorage,
            Verification::Verified { content: as_state },
        );
        assert!(!state_copy.reconstructs(&as_content));
        assert_eq!(
            eviction_action(&clean(as_content), &[state_copy], WriteBack::Unavailable),
            EvictionAction::Retain {
                because: NotDroppable::NoVerifiedCopy
            }
        );
    }
}
