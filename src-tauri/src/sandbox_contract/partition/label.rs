//! Confidentiality, provenance and integrity labels (VM part §9.1, lines 2303 and 2320).
//!
//! A label only grows: joining adds secrecy tags and provenance and lowers integrity, and
//! nothing in this module removes a tag. Labels come from trusted policy and explicit data
//! provenance; a model's assertion that content is harmless is representable only so it
//! can be refused (line 2320).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::names::LabelTag;

/// Whether data may be trusted as instructions or code. Data touched by untrusted code or
/// fetched from a registry is untrusted, and preserved data remains potentially hostile
/// (VM part §1.4, §5.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Integrity {
    Trusted,
    Untrusted,
}

/// A data label (line 2303 "input provenance/confidentiality labels"): the private sources
/// whose content it may hold, every source it derives from, and its integrity.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    secrecy: BTreeSet<LabelTag>,
    provenance: BTreeSet<LabelTag>,
    integrity: Integrity,
}

impl Label {
    /// What an empty compartment holds: public, no provenance, trusted.
    pub fn bottom() -> Self {
        Self {
            secrecy: BTreeSet::new(),
            provenance: BTreeSet::new(),
            integrity: Integrity::Trusted,
        }
    }

    /// Public data from one provenance source.
    pub fn public(source: LabelTag, integrity: Integrity) -> Self {
        Self {
            secrecy: BTreeSet::new(),
            provenance: BTreeSet::from([source]),
            integrity,
        }
    }

    /// Private data of one source: the source is both its secrecy tag and its provenance.
    pub fn private(source: LabelTag, integrity: Integrity) -> Self {
        Self {
            secrecy: BTreeSet::from([source.clone()]),
            provenance: BTreeSet::from([source]),
            integrity,
        }
    }

    /// The private sources this data may contain; empty means public.
    pub fn secrecy(&self) -> &BTreeSet<LabelTag> {
        &self.secrecy
    }

    /// Every source this data derives from.
    pub fn provenance(&self) -> &BTreeSet<LabelTag> {
        &self.provenance
    }

    pub fn integrity(&self) -> Integrity {
        self.integrity
    }

    /// Whether no private source is attached.
    pub fn is_public(&self) -> bool {
        self.secrecy.is_empty()
    }

    /// The least label above both (line 2320: labels remain attached to derived outputs).
    pub fn join(&self, other: &Label) -> Label {
        let mut joined = self.clone();
        joined.join_in(other);
        joined
    }

    /// Joins `other` into this label.
    pub fn join_in(&mut self, other: &Label) {
        self.secrecy.extend(other.secrecy.iter().cloned());
        self.provenance.extend(other.provenance.iter().cloned());
        if other.integrity == Integrity::Untrusted {
            self.integrity = Integrity::Untrusted;
        }
    }

    /// Adds one private source.
    pub fn with_secrecy(mut self, source: LabelTag) -> Self {
        self.provenance.insert(source.clone());
        self.secrecy.insert(source);
        self
    }

    /// Marks the data untrusted.
    pub fn untrusted(mut self) -> Self {
        self.integrity = Integrity::Untrusted;
        self
    }

    /// Whether this label is at or below `other`: every tag is kept and integrity is not
    /// raised.
    pub fn flows_to(&self, other: &Label) -> bool {
        self.secrecy.is_subset(&other.secrecy)
            && self.provenance.is_subset(&other.provenance)
            && (self.integrity == Integrity::Trusted || other.integrity == Integrity::Untrusted)
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let list = |tags: &BTreeSet<LabelTag>| {
            tags.iter()
                .map(LabelTag::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        };
        if self.secrecy.is_empty() {
            f.write_str("public")?;
        } else {
            write!(f, "private ({})", list(&self.secrecy))?;
        }
        match self.integrity {
            Integrity::Trusted => f.write_str(", trusted"),
            Integrity::Untrusted => f.write_str(", untrusted"),
        }
    }
}

strict_tagged_enum! {
/// Where a source label comes from (line 2320). Only trusted policy and explicit data
/// provenance are accepted; a model's assertion is never a label, so a workflow whose
/// source carries one is refused.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum LabelOrigin (tag = "origin", wire = LabelOriginWire, wire_name = "LabelOriginWire") {
    /// A rule of the host's trusted policy assigned the label.
    TrustedPolicy { rule: LabelTag },
    /// The data's recorded provenance assigned it, such as a registry pin or a granted
    /// project root.
    ExplicitProvenance { source: LabelTag },
    /// A model asserted it. Refused (line 2320).
    ModelAssertion { model: LabelTag },
}
}

impl LabelOrigin {
    /// Whether the label may be used: only trusted policy or explicit provenance.
    pub fn is_accepted(&self) -> bool {
        !matches!(self, Self::ModelAssertion { .. })
    }
}
