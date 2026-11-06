//! Remote objects and sources (table line 544): original or publisher-prepared
//! artifacts, fetched in resumable ranges whose integrity is checked, under egress and
//! access policy.
//!
//! A remote lists each artifact by class and content key, with ranges that tile it
//! exactly, each with a digest bound to its offset and true length. A download is a
//! [`RangeTransfer`] into the requester's own scope: a range counts only once its bytes
//! match, an interrupted download resumes with the ranges still unverified, and a
//! verified range is never fetched again. Every range fetched is charged to the remote's
//! explicit egress budget, including ranges that fail verification, and nothing raises
//! that budget implicitly (S3.7). Only scopes the access policy names are served. The
//! catalog's importer then verifies and publishes the whole object (T05).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::object::{Consumer, ObjectCopy, ObjectRef};
use super::source::{OfferRefusal, SourceOffer, SourcePath, TierRefusal};
use super::{checked_sum, Tier};
use crate::foundation::catalog::{ArtifactClass, Scope};
use crate::foundation::ids::{ContentKey, Digest, DigestBuilder};
use crate::model_memory::math::SourceId;
use crate::model_memory::residency::eviction::{CopyTier, ReconstructibleCopy, Verification};

/// Domain of [`range_digest`].
pub const RANGE_DOMAIN: &str = "yougori/model-memory/tiers/range/v1";

/// The digest a range's bytes must match: its offset, true length and bytes under
/// [`RANGE_DOMAIN`].
pub fn range_digest(offset: u64, bytes: &[u8]) -> Digest {
    DigestBuilder::new(RANGE_DOMAIN)
        .u64(offset)
        .bytes(bytes)
        .finish()
}

/// One range of a remote artifact and the digest its bytes must match.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RangeSpec {
    pub offset: u64,
    pub length_bytes: u64,
    pub digest: Digest,
}

/// What a remote holds (table line 544).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteContent {
    Original,
    PublisherPrepared,
}

/// A remote's egress and access policy (table line 544; S3.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemotePolicy {
    /// Scopes this remote serves.
    pub access: BTreeSet<Scope>,
    /// Bytes this remote may send in total; explicit, never raised by a request.
    pub egress_budget_bytes: u64,
}

/// Why a remote refused (table line 544).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteRefusal {
    /// The access policy does not name the scope.
    AccessDenied {
        scope: Scope,
    },
    /// A download goes into the requester's own scope only.
    NotRequestersScope {
        object: ObjectRef,
    },
    NoRanges,
    ZeroLengthRange {
        index: usize,
    },
    /// Ranges must start at zero and follow each other without gaps or overlaps.
    RangeGap {
        index: usize,
        expected_offset: u64,
        offset: u64,
    },
    AlreadyListed {
        class: ArtifactClass,
        content: ContentKey,
    },
    NotListed {
        class: ArtifactClass,
        content: ContentKey,
    },
    UnknownRange {
        index: usize,
    },
    /// A verified range is never fetched again.
    AlreadyVerified {
        index: usize,
    },
    EgressBudgetExhausted {
        egress_budget_bytes: u64,
        egress_used_bytes: u64,
        requested_bytes: u64,
    },
    /// The bytes do not match the range's digest or length; the range stays pending.
    IntegrityMismatch {
        index: usize,
    },
    Overflow,
}

impl fmt::Display for RemoteRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AccessDenied { scope } => {
                write!(f, "the remote's access policy does not serve {scope}")
            }
            Self::NotRequestersScope { object } => write!(
                f,
                "{object} is not in the requester's own scope; a download goes only there"
            ),
            Self::NoRanges => f.write_str("an artifact has at least one range"),
            Self::ZeroLengthRange { index } => write!(f, "range {index} is empty"),
            Self::RangeGap {
                index,
                expected_offset,
                offset,
            } => write!(
                f,
                "range {index} starts at {offset}, not at {expected_offset} where the previous \
                 one ended"
            ),
            Self::AlreadyListed { class, content } => {
                write!(f, "{class} {content} is already listed")
            }
            Self::NotListed { class, content } => write!(f, "{class} {content} is not listed"),
            Self::UnknownRange { index } => write!(f, "range {index} does not exist"),
            Self::AlreadyVerified { index } => {
                write!(f, "range {index} is verified and is not fetched again")
            }
            Self::EgressBudgetExhausted {
                egress_budget_bytes,
                egress_used_bytes,
                requested_bytes,
            } => write!(
                f,
                "{requested_bytes} more bytes exceed the egress budget: {egress_used_bytes} of \
                 {egress_budget_bytes} are used"
            ),
            Self::IntegrityMismatch { index } => write!(
                f,
                "range {index} does not match its digest; it stays pending and is fetched again"
            ),
            Self::Overflow => f.write_str("a byte total does not fit in 64 bits"),
        }
    }
}

impl std::error::Error for RemoteRefusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Listed {
    content: RemoteContent,
    ranges: Vec<RangeSpec>,
    total_bytes: u64,
}

/// The resumable state of one download: which ranges are verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RangeTransfer {
    object: ObjectRef,
    ranges: Vec<RangeSpec>,
    verified: Vec<bool>,
}

impl RangeTransfer {
    /// The object the download will import.
    pub fn object(&self) -> &ObjectRef {
        &self.object
    }

    /// Ranges still to fetch, in order; resuming fetches only these.
    pub fn pending(&self) -> Vec<usize> {
        self.verified
            .iter()
            .enumerate()
            .filter(|(_, verified)| !**verified)
            .map(|(index, _)| index)
            .collect()
    }

    pub fn pending_bytes(&self) -> u64 {
        self.bytes_where(false)
    }

    pub fn verified_bytes(&self) -> u64 {
        self.bytes_where(true)
    }

    pub fn is_complete(&self) -> bool {
        self.verified.iter().all(|verified| *verified)
    }

    fn bytes_where(&self, verified: bool) -> u64 {
        self.ranges
            .iter()
            .zip(&self.verified)
            .filter(|(_, state)| **state == verified)
            .fold(0u64, |total, (range, _)| {
                total.saturating_add(range.length_bytes)
            })
    }
}

/// One remote object store or source (table line 544).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteSource {
    policy: RemotePolicy,
    egress_used_bytes: u64,
    listed: BTreeMap<(ArtifactClass, ContentKey), Listed>,
}

impl RemoteSource {
    pub fn new(policy: RemotePolicy) -> Self {
        Self {
            policy,
            egress_used_bytes: 0,
            listed: BTreeMap::new(),
        }
    }

    pub fn policy(&self) -> &RemotePolicy {
        &self.policy
    }

    pub fn egress_used_bytes(&self) -> u64 {
        self.egress_used_bytes
    }

    pub fn egress_remaining_bytes(&self) -> u64 {
        self.policy
            .egress_budget_bytes
            .saturating_sub(self.egress_used_bytes)
    }

    /// Lists an artifact with ranges that tile it exactly; returns its size.
    pub fn list(
        &mut self,
        class: ArtifactClass,
        content: ContentKey,
        kind: RemoteContent,
        ranges: Vec<RangeSpec>,
    ) -> Result<u64, RemoteRefusal> {
        if self.listed.contains_key(&(class, content)) {
            return Err(RemoteRefusal::AlreadyListed { class, content });
        }
        if ranges.is_empty() {
            return Err(RemoteRefusal::NoRanges);
        }
        let mut expected_offset = 0u64;
        for (index, range) in ranges.iter().enumerate() {
            if range.length_bytes == 0 {
                return Err(RemoteRefusal::ZeroLengthRange { index });
            }
            if range.offset != expected_offset {
                return Err(RemoteRefusal::RangeGap {
                    index,
                    expected_offset,
                    offset: range.offset,
                });
            }
            expected_offset = range
                .offset
                .checked_add(range.length_bytes)
                .ok_or(RemoteRefusal::Overflow)?;
        }
        self.listed.insert(
            (class, content),
            Listed {
                content: kind,
                ranges,
                total_bytes: expected_offset,
            },
        );
        Ok(expected_offset)
    }

    /// What a listed artifact is.
    pub fn content_of(&self, class: ArtifactClass, content: ContentKey) -> Option<RemoteContent> {
        self.listed
            .get(&(class, content))
            .map(|listed| listed.content)
    }

    /// Starts a download of `object` for `requester`: into the requester's own scope,
    /// which the access policy must serve.
    pub fn begin(
        &self,
        object: &ObjectRef,
        requester: &Consumer,
    ) -> Result<RangeTransfer, RemoteRefusal> {
        if object.scope != requester.scope() {
            return Err(RemoteRefusal::NotRequestersScope {
                object: object.clone(),
            });
        }
        let listed = self.served(object)?;
        Ok(RangeTransfer {
            object: object.clone(),
            ranges: listed.ranges.clone(),
            verified: vec![false; listed.ranges.len()],
        })
    }

    /// Fetches one pending range: charges its length to the egress budget, then marks it
    /// verified only if `received` matches its length and digest.
    pub fn fetch(
        &mut self,
        transfer: &mut RangeTransfer,
        index: usize,
        received: &[u8],
    ) -> Result<(), RemoteRefusal> {
        let listed = self.served(&transfer.object)?;
        if listed.ranges != transfer.ranges {
            return Err(RemoteRefusal::NotListed {
                class: transfer.object.class,
                content: transfer.object.content,
            });
        }
        let range = *transfer
            .ranges
            .get(index)
            .ok_or(RemoteRefusal::UnknownRange { index })?;
        if transfer.verified.get(index).copied().unwrap_or(false) {
            return Err(RemoteRefusal::AlreadyVerified { index });
        }
        let egress_total = checked_sum([self.egress_used_bytes, range.length_bytes])
            .ok_or(RemoteRefusal::Overflow)?;
        if egress_total > self.policy.egress_budget_bytes {
            return Err(RemoteRefusal::EgressBudgetExhausted {
                egress_budget_bytes: self.policy.egress_budget_bytes,
                egress_used_bytes: self.egress_used_bytes,
                requested_bytes: range.length_bytes,
            });
        }
        self.egress_used_bytes = egress_total;
        let intact = u64::try_from(received.len()).ok() == Some(range.length_bytes)
            && range_digest(range.offset, received) == range.digest;
        if !intact {
            return Err(RemoteRefusal::IntegrityMismatch { index });
        }
        if let Some(verified) = transfer.verified.get_mut(index) {
            *verified = true;
        }
        Ok(())
    }

    /// The remote's copy of an object it serves. Nothing here verified it, so it never
    /// reconstructs a dropped GPU copy (T08).
    pub fn copy_of(&self, object: &ObjectRef) -> Option<ObjectCopy> {
        self.served(object).ok().map(|_| ObjectCopy {
            object: object.clone(),
            holder: None,
            copy: ReconstructibleCopy {
                tier: CopyTier::RemoteSource,
                verification: Verification::Unverified,
            },
        })
    }

    /// Offers a listed artifact to `requester` for import into the requester's own scope,
    /// where [`RemoteSource::begin`] puts a download, if the access policy serves it; the
    /// offer covers no more than the remaining egress budget.
    pub fn offer(
        &self,
        source: SourceId,
        object: &ObjectRef,
        requester: &Consumer,
        path: SourcePath,
    ) -> Result<SourceOffer, OfferRefusal> {
        let refuse =
            |refusal| OfferRefusal::new(&source, Tier::Remote, TierRefusal::Remote(refusal));
        if object.scope != requester.scope() {
            return Err(refuse(RemoteRefusal::NotRequestersScope {
                object: object.clone(),
            }));
        }
        let listed = self.served(object).map_err(refuse)?;
        let remaining_bytes = self.egress_remaining_bytes();
        if remaining_bytes == 0 {
            return Err(refuse(RemoteRefusal::EgressBudgetExhausted {
                egress_budget_bytes: self.policy.egress_budget_bytes,
                egress_used_bytes: self.egress_used_bytes,
                requested_bytes: listed.total_bytes,
            }));
        }
        let covers_bytes = listed.total_bytes.min(remaining_bytes);
        Ok(SourceOffer::new(
            Tier::Remote,
            source,
            object.clone(),
            requester,
            path,
            covers_bytes,
        ))
    }

    fn served(&self, object: &ObjectRef) -> Result<&Listed, RemoteRefusal> {
        let listed =
            self.listed
                .get(&(object.class, object.content))
                .ok_or(RemoteRefusal::NotListed {
                    class: object.class,
                    content: object.content,
                })?;
        if !self.policy.access.contains(&object.scope) {
            return Err(RemoteRefusal::AccessDenied {
                scope: object.scope.clone(),
            });
        }
        Ok(listed)
    }
}

#[cfg(test)]
mod tests;
