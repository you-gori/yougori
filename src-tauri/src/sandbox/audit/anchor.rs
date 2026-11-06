//! The optional remote-anchored head of an audit stream (VM-W42 "optional remote
//! anchoring" at line 2665; §8.2 at line 2447: "Signed/remote-anchored heads make
//! tampering detectable under stated custody assumptions; a same-user local log is not
//! WORM").
//!
//! A [`HeadAnchor`] is a port: somewhere the stream publishes its head that the stream's
//! writer does not control. Comparing stored segments with the anchored head shows
//! whether the chain was cut or rewritten after the anchor was published. The verdict is
//! detection; nothing here prevents a host administrator from rewriting the store and the
//! anchor together, and no text in this module says otherwise.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::segment::StoredSegment;
use crate::foundation::events::{EventSequence, JournalHead, JournalId};
use crate::foundation::ids::MonotonicTime;

/// The custody assumptions under which a verified chain and anchor mean anything (§8.2
/// line 2447). Shown wherever an [`AnchorVerdict`] is shown.
pub const CUSTODY_STATEMENT: &str = "A verified chain shows no edit, removal or reordering \
of records up to the anchored head, provided the anchor is held where the stream's writer \
and the host administrator cannot change it and the verifier reads it from there. The \
chain and the anchor detect tampering after the fact; they do not prevent it. Whoever \
controls the host, its storage and the anchor can rewrite all three, and a same-user \
local log is not write-once storage.";

/// A head published to the anchor: the stream, the head of its chain, the segment the
/// head was in and when the stream published it on its own clock.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnchoredHead {
    stream: JournalId,
    head: JournalHead,
    segment: u64,
    anchored_at: MonotonicTime,
}

impl AnchoredHead {
    /// An empty head anchors nothing and is refused.
    pub fn new(
        head: JournalHead,
        segment: u64,
        anchored_at: MonotonicTime,
    ) -> Result<Self, AnchorRefusal> {
        if head.last.is_none() {
            return Err(AnchorRefusal::EmptyHead);
        }
        Ok(Self {
            stream: head.journal.clone(),
            head,
            segment,
            anchored_at,
        })
    }

    pub fn stream(&self) -> &JournalId {
        &self.stream
    }

    pub fn head(&self) -> &JournalHead {
        &self.head
    }

    /// The sequence of the anchored record.
    pub fn sequence(&self) -> EventSequence {
        self.head.last.unwrap_or(EventSequence::FIRST)
    }

    pub fn segment(&self) -> u64 {
        self.segment
    }

    pub fn anchored_at(&self) -> MonotonicTime {
        self.anchored_at
    }
}

/// Why the anchor did not take or return a head. A refusal never stops the stream:
/// appends go on, and the head stays pending until the anchor takes it (VM-W42 "delayed
/// anchor tested").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnchorRefusal {
    /// The head names no record.
    EmptyHead,
    /// The anchor could not be reached; publishing is delayed.
    Unreachable,
    /// The anchor refused the head.
    Rejected,
    /// The anchor already holds a later head of this stream; heads only move forward.
    Regressed {
        held: EventSequence,
        offered: EventSequence,
    },
    /// No anchor is configured for this stream.
    NotConfigured,
}

impl fmt::Display for AnchorRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyHead => f.write_str("an empty head anchors nothing"),
            Self::Unreachable => {
                f.write_str("the anchor could not be reached; publishing is delayed")
            }
            Self::Rejected => f.write_str("the anchor refused the head"),
            Self::Regressed { held, offered } => write!(
                f,
                "the anchor holds record {held} and refuses the earlier record {offered}"
            ),
            Self::NotConfigured => f.write_str("no anchor is configured for this stream"),
        }
    }
}

impl std::error::Error for AnchorRefusal {}

/// Where a stream publishes its head: a port on storage the stream's writer does not
/// control (§8.2). Publishing may be delayed or refused; it never waits on, and is never
/// waited on by, an append.
pub trait HeadAnchor {
    /// Holds `head` after every head of its stream held before it. `Ok` once it is held;
    /// a later head of the same stream replaces it, and an earlier one is refused.
    fn publish(&mut self, head: &AnchoredHead) -> Result<(), AnchorRefusal>;

    /// The latest head held for `stream`.
    fn latest(&self, stream: &JournalId) -> Result<Option<AnchoredHead>, AnchorRefusal>;
}

/// The anchor of a stream that has none: it holds nothing and refuses every head.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NoAnchor;

impl HeadAnchor for NoAnchor {
    fn publish(&mut self, _head: &AnchoredHead) -> Result<(), AnchorRefusal> {
        Err(AnchorRefusal::NotConfigured)
    }

    fn latest(&self, _stream: &JournalId) -> Result<Option<AnchoredHead>, AnchorRefusal> {
        Ok(None)
    }
}

/// What a stream knows about its anchor: the last head the anchor took, a head it still
/// owes the anchor, and how often the anchor refused.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct AnchorState {
    published: Option<AnchoredHead>,
    pending: Option<JournalHead>,
    publications: u64,
    refusals: u64,
}

impl AnchorState {
    pub fn published(&self) -> Option<&AnchoredHead> {
        self.published.as_ref()
    }

    /// A head the anchor has not taken yet (a delayed anchor).
    pub fn pending(&self) -> Option<&JournalHead> {
        self.pending.as_ref()
    }

    pub fn publications(&self) -> u64 {
        self.publications
    }

    pub fn refusals(&self) -> u64 {
        self.refusals
    }

    /// How many durable records `head` is past the last anchored head.
    pub fn lag_records(&self, head: &JournalHead) -> u64 {
        let anchored = self
            .published
            .as_ref()
            .map_or(0, |published| published.sequence().get());
        head.last
            .map_or(0, EventSequence::get)
            .saturating_sub(anchored)
    }

    pub(super) fn record_publication(&mut self, head: AnchoredHead) {
        self.published = Some(head);
        self.pending = None;
        self.publications = self.publications.saturating_add(1);
    }

    pub(super) fn record_refusal(&mut self, head: JournalHead) {
        self.pending = Some(head);
        self.refusals = self.refusals.saturating_add(1);
    }
}

strict_tagged_enum! {
    /// What comparing stored segments with the anchored head shows. Each verdict is
    /// detection under [`CUSTODY_STATEMENT`]; none is a guarantee of what happened
    /// outside the chain.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum AnchorVerdict (tag = "verdict", wire = AnchorVerdictWire, wire_name = "AnchorVerdictWire") {
        /// Nothing is anchored for the stream; the chain is checked only against itself.
        NotAnchored,
        /// The stored chain holds the anchored record with the anchored digest.
        Reaches { anchored: EventSequence },
        /// The stored chain ends before the anchored record: records after
        /// `stored_through` were removed after the head was anchored.
        Truncated {
            anchored: EventSequence,
            stored_through: Option<EventSequence>,
        },
        /// The stored record at the anchored sequence has another digest: the chain was
        /// rewritten after the head was anchored.
        Rewritten { anchored: EventSequence },
        /// The anchored head belongs to another stream.
        OtherStream,
        /// The anchored record was dropped under storage's retention bound, before the
        /// chain storage still holds: nothing is left to compare it with.
        Dropped { anchored: EventSequence },
    }
}

impl AnchorVerdict {
    /// Whether the verdict allows the stream to continue from what is stored or from
    /// the anchored head. A rewrite does not: the chain cannot be continued honestly.
    pub const fn allows_resume(&self) -> bool {
        matches!(
            self,
            Self::NotAnchored
                | Self::Reaches { .. }
                | Self::Truncated { .. }
                | Self::Dropped { .. }
        )
    }

    /// The plain statement of the verdict, worded as detection only.
    pub const fn statement(&self) -> &'static str {
        match self {
            Self::NotAnchored => "no head is anchored; the chain was checked against itself only",
            Self::Reaches { .. } => {
                "the stored chain reaches the anchored head unchanged; no edit, removal or \
                 reordering up to that record was detected"
            }
            Self::Truncated { .. } => {
                "the stored chain ends before the anchored head: records were removed after \
                 the head was anchored"
            }
            Self::Rewritten { .. } => {
                "the stored record at the anchored sequence differs from the anchored head: \
                 the chain was rewritten after the head was anchored"
            }
            Self::OtherStream => "the anchored head belongs to another stream",
            Self::Dropped { .. } => {
                "the anchored record was dropped under the retention bound; the retained \
                 chain was checked against itself only"
            }
        }
    }
}

impl fmt::Display for AnchorVerdict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.statement())
    }
}

/// Compares stored segments of `stream` with `anchored`. The segments are taken as
/// stored, verified or not: a chain that fails [`verify_segments`] is refused there, and
/// this comparison adds what only the anchor can show.
///
/// [`verify_segments`]: super::verify_segments
pub fn compare_with_anchor(
    stream: &JournalId,
    segments: &[StoredSegment],
    anchored: Option<&AnchoredHead>,
) -> AnchorVerdict {
    let Some(anchored) = anchored else {
        return AnchorVerdict::NotAnchored;
    };
    if anchored.stream() != stream {
        return AnchorVerdict::OtherStream;
    }
    let sequence = anchored.sequence();
    let stored = segments
        .iter()
        .flat_map(|segment| segment.records.iter())
        .find(|record| record.sequence() == sequence);
    match stored {
        Some(record) if record.digest() == anchored.head().digest => {
            AnchorVerdict::Reaches { anchored: sequence }
        }
        Some(_) => AnchorVerdict::Rewritten { anchored: sequence },
        None => {
            let stored_through = segments
                .iter()
                .flat_map(|segment| segment.records.iter())
                .map(|record| record.sequence())
                .max();
            if stored_through.is_some_and(|through| through >= sequence) {
                AnchorVerdict::Rewritten { anchored: sequence }
            } else {
                AnchorVerdict::Truncated {
                    anchored: sequence,
                    stored_through,
                }
            }
        }
    }
}

/// [`compare_with_anchor`] for segments that retention cut: `retained_after` is the head
/// the first retained segment continues ([`RetainedStart::after`]), and `None` when the
/// segments start at genesis. An anchored record before that head was dropped
/// ([`AnchorVerdict::Dropped`]); one at that head is compared with it.
///
/// [`RetainedStart::after`]: super::RetainedStart::after
pub fn compare_retained_with_anchor(
    stream: &JournalId,
    segments: &[StoredSegment],
    retained_after: Option<&JournalHead>,
    anchored: Option<&AnchoredHead>,
) -> AnchorVerdict {
    let (Some(after), Some(found)) = (retained_after, anchored) else {
        return compare_with_anchor(stream, segments, anchored);
    };
    if found.stream() != stream {
        return AnchorVerdict::OtherStream;
    }
    let sequence = found.sequence();
    match after.last {
        Some(last) if sequence < last => AnchorVerdict::Dropped { anchored: sequence },
        Some(last) if sequence == last && after.digest == found.head().digest => {
            AnchorVerdict::Reaches { anchored: sequence }
        }
        Some(last) if sequence == last => AnchorVerdict::Rewritten { anchored: sequence },
        _ => compare_with_anchor(stream, segments, anchored),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::events::ProducerId;
    use crate::foundation::ids::digest;

    fn head(last: Option<u64>) -> JournalHead {
        JournalHead {
            journal: JournalId::new("engine").unwrap(),
            owner: ProducerId::new("engine.audit").unwrap(),
            last: last.and_then(EventSequence::new),
            digest: digest("yougori/test/head/v1", &[&last.unwrap_or(0).to_be_bytes()]),
        }
    }

    #[test]
    fn an_empty_head_is_not_anchored() {
        assert_eq!(
            AnchoredHead::new(head(None), 0, MonotonicTime::ZERO).err(),
            Some(AnchorRefusal::EmptyHead)
        );
        let anchored = AnchoredHead::new(head(Some(3)), 1, MonotonicTime::from_nanos(9)).unwrap();
        assert_eq!(anchored.sequence().get(), 3);
        assert_eq!(anchored.segment(), 1);
        assert_eq!(anchored.anchored_at(), MonotonicTime::from_nanos(9));
        assert_eq!(anchored.stream().as_str(), "engine");
    }

    #[test]
    fn the_lag_counts_records_past_the_anchored_head() {
        let mut state = AnchorState::default();
        assert_eq!(state.lag_records(&head(Some(5))), 5);
        state.record_publication(AnchoredHead::new(head(Some(3)), 0, MonotonicTime::ZERO).unwrap());
        assert_eq!(state.lag_records(&head(Some(5))), 2);
        assert_eq!(state.lag_records(&head(Some(3))), 0);
        state.record_refusal(head(Some(7)));
        assert_eq!(state.pending(), Some(&head(Some(7))));
        assert_eq!((state.publications(), state.refusals()), (1, 1));
        let mut none = NoAnchor;
        assert_eq!(
            none.publish(state.published().unwrap()),
            Err(AnchorRefusal::NotConfigured)
        );
        assert_eq!(none.latest(&head(None).journal), Ok(None));
    }

    #[test]
    fn verdicts_speak_of_detection_only() {
        let verdicts = [
            AnchorVerdict::NotAnchored,
            AnchorVerdict::Reaches {
                anchored: EventSequence::FIRST,
            },
            AnchorVerdict::Truncated {
                anchored: EventSequence::FIRST,
                stored_through: None,
            },
            AnchorVerdict::Rewritten {
                anchored: EventSequence::FIRST,
            },
            AnchorVerdict::OtherStream,
            AnchorVerdict::Dropped {
                anchored: EventSequence::FIRST,
            },
        ];
        for verdict in verdicts {
            let text = verdict.to_string().to_ascii_lowercase();
            for forbidden in ["prevent", "worm", "secure", "tamper-proof", "guarantee"] {
                assert!(!text.contains(forbidden), "{verdict:?}: {text}");
            }
            let json = serde_json::to_value(verdict).unwrap();
            assert_eq!(
                serde_json::from_value::<AnchorVerdict>(json).unwrap(),
                verdict
            );
        }
        assert!(!AnchorVerdict::Rewritten {
            anchored: EventSequence::FIRST
        }
        .allows_resume());
        assert!(serde_json::from_str::<AnchorVerdict>(
            r#"{"verdict":"not_anchored","proof":true}"#
        )
        .is_err());
        let custody = CUSTODY_STATEMENT.to_ascii_lowercase();
        assert!(custody.contains("do not prevent"));
        assert!(custody.contains("not write-once"));
    }

    #[test]
    fn a_head_before_what_retention_kept_is_reported_as_dropped() {
        let stream = JournalId::new("engine").unwrap();
        let anchored =
            |last: u64| AnchoredHead::new(head(Some(last)), 0, MonotonicTime::ZERO).unwrap();
        let after = head(Some(5));
        let compare = |found: &AnchoredHead| {
            compare_retained_with_anchor(&stream, &[], Some(&after), Some(found))
        };
        assert_eq!(
            compare(&anchored(3)),
            AnchorVerdict::Dropped {
                anchored: EventSequence::new(3).unwrap()
            }
        );
        assert_eq!(
            compare(&anchored(5)),
            AnchorVerdict::Reaches {
                anchored: EventSequence::new(5).unwrap()
            }
        );
        let other_digest = AnchoredHead::new(
            JournalHead {
                digest: digest("yougori/test/other/v1", &[]),
                ..head(Some(5))
            },
            0,
            MonotonicTime::ZERO,
        )
        .unwrap();
        assert_eq!(
            compare(&other_digest),
            AnchorVerdict::Rewritten {
                anchored: EventSequence::new(5).unwrap()
            }
        );
        // Past the retained start the stored segments decide, as without retention.
        assert_eq!(
            compare(&anchored(7)),
            AnchorVerdict::Truncated {
                anchored: EventSequence::new(7).unwrap(),
                stored_through: None
            }
        );
        let foreign = AnchoredHead::new(
            JournalHead {
                journal: JournalId::new("warden").unwrap(),
                ..head(Some(3))
            },
            0,
            MonotonicTime::ZERO,
        )
        .unwrap();
        assert_eq!(compare(&foreign), AnchorVerdict::OtherStream);
        assert_eq!(
            compare_retained_with_anchor(&stream, &[], None, Some(&anchored(3))),
            compare_with_anchor(&stream, &[], Some(&anchored(3)))
        );
        assert_eq!(
            compare_retained_with_anchor(&stream, &[], Some(&after), None),
            AnchorVerdict::NotAnchored
        );
    }

    #[test]
    fn refusals_describe_themselves() {
        for refusal in [
            AnchorRefusal::EmptyHead,
            AnchorRefusal::Unreachable,
            AnchorRefusal::Rejected,
            AnchorRefusal::Regressed {
                held: EventSequence::new(4).unwrap(),
                offered: EventSequence::FIRST,
            },
            AnchorRefusal::NotConfigured,
        ] {
            assert!(!refusal.to_string().is_empty());
        }
    }
}
