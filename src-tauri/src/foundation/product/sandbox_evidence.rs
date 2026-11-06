//! A launched sandbox's facts with their evidence (VM-W04, VM-W53: "A user can understand
//! what will run, what it can read/release and why a capability is unavailable; no new
//! grid/security tab maze").
//!
//! The contract's own shape of V17's shown view: four fixed sections in V17's order and
//! with V17's titles, each line a fact's kind, its wording and its one [`Evidence`] state,
//! and V17's standing notice. The engine's `product_views` module converts V17's shown view
//! into it, label for label; its tests check that the titles and notice here are V17's.
//! Reading one back refuses a missing, repeated or retitled section and any other notice,
//! so a stored view cannot be edited into a certificate.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::evidence::Evidence;
use super::text::ShownText;
use crate::foundation::ids::{validate_identifier, Digest, IdError};

/// V17's standing notice: an evidence record, not a certificate (§8.1).
pub const SANDBOX_NOTICE: &str = "This view is an evidence record, not a certificate. \
     Observed and verified facts hold only while current under the configuration in \
     force; guest, launch request, declaration and contract statements are assertions; \
     a contract states what is granted, not that anything enforces it.";

/// One of V17's four sections.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxSection {
    WhatRuns,
    ReadsAndKeeps,
    Releases,
    Unavailable,
}

impl SandboxSection {
    /// Every section, in V17's display order.
    pub const ALL: [Self; 4] = [
        Self::WhatRuns,
        Self::ReadsAndKeeps,
        Self::Releases,
        Self::Unavailable,
    ];

    /// V17's plain-language title.
    pub const fn title(self) -> &'static str {
        match self {
            Self::WhatRuns => "What will run",
            Self::ReadsAndKeeps => "What it can read, write and keep",
            Self::Releases => "What it can release, and where",
            Self::Unavailable => "What is unavailable, and why",
        }
    }
}

/// One fact as shown: its kind (V17's fact tag), its wording and its one evidence state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CapabilityLine {
    kind: String,
    text: ShownText,
    evidence: Evidence,
}

impl CapabilityLine {
    /// A fact of `kind`, a fixed identifier of the source's vocabulary, worded `text`, on
    /// `evidence`. [`CapabilityLine::check`] checks the kind's grammar.
    pub fn new(kind: &'static str, text: &str, evidence: Evidence) -> Self {
        Self {
            kind: kind.to_owned(),
            text: ShownText::new(text),
            evidence,
        }
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn text(&self) -> &ShownText {
        &self.text
    }

    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }

    /// The kind follows the ids.rs identifier grammar.
    pub fn check(&self) -> Result<(), IdError> {
        validate_identifier(&self.kind)
    }

    pub(super) fn with_evidence(&self, evidence: Evidence) -> Self {
        Self {
            kind: self.kind.clone(),
            text: self.text.clone(),
            evidence,
        }
    }
}

impl fmt::Display for CapabilityLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.text, self.evidence)
    }
}

impl<'de> Deserialize<'de> for CapabilityLine {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: String,
            text: ShownText,
            evidence: Evidence,
        }
        let wire = Wire::deserialize(deserializer)?;
        let line = Self {
            kind: wire.kind,
            text: wire.text,
            evidence: wire.evidence,
        };
        line.check().map_err(serde::de::Error::custom)?;
        Ok(line)
    }
}

/// One section with its lines, in the view's order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SectionShown {
    section: SandboxSection,
    title: &'static str,
    lines: Vec<CapabilityLine>,
}

impl SectionShown {
    pub fn section(&self) -> SandboxSection {
        self.section
    }

    pub fn title(&self) -> &'static str {
        self.title
    }

    pub fn lines(&self) -> &[CapabilityLine] {
        &self.lines
    }

    pub(super) fn with_lines(&self, lines: Vec<CapabilityLine>) -> Self {
        Self {
            section: self.section,
            title: self.title,
            lines,
        }
    }
}

impl<'de> Deserialize<'de> for SectionShown {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            section: SandboxSection,
            title: String,
            lines: Vec<CapabilityLine>,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.title != wire.section.title() {
            return Err(serde::de::Error::custom(format!(
                "the section {:?} is titled \"{}\"",
                wire.section,
                wire.section.title()
            )));
        }
        Ok(Self {
            section: wire.section,
            title: wire.section.title(),
            lines: wire.lines,
        })
    }
}

/// A launched sandbox's facts with their evidence: V17's shown view, in the contract's
/// shape.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SandboxEvidence {
    /// The digest of the stored V17 view the labels were computed from.
    view: Digest,
    launch_record: Digest,
    /// The four sections, each listed even when empty, in [`SandboxSection::ALL`] order.
    sections: Vec<SectionShown>,
    /// V17's standing notice: an evidence record, not a certificate.
    notice: &'static str,
}

impl SandboxEvidence {
    /// The view `view` of the launch record `launch_record`, with each section's lines
    /// given in [`SandboxSection::ALL`] order.
    pub fn new(view: Digest, launch_record: Digest, lines: [Vec<CapabilityLine>; 4]) -> Self {
        Self {
            view,
            launch_record,
            sections: SandboxSection::ALL
                .into_iter()
                .zip(lines)
                .map(|(section, lines)| SectionShown {
                    section,
                    title: section.title(),
                    lines,
                })
                .collect(),
            notice: SANDBOX_NOTICE,
        }
    }

    pub fn view(&self) -> Digest {
        self.view
    }

    pub fn launch_record(&self) -> Digest {
        self.launch_record
    }

    pub fn sections(&self) -> &[SectionShown] {
        &self.sections
    }

    /// The lines of `section`.
    pub fn section(&self, section: SandboxSection) -> &[CapabilityLine] {
        self.sections
            .iter()
            .find(|shown| shown.section == section)
            .map_or(&[], |shown| shown.lines.as_slice())
    }

    /// Every line, in order.
    pub fn lines(&self) -> impl Iterator<Item = &CapabilityLine> {
        self.sections
            .iter()
            .flat_map(|section| section.lines.iter())
    }

    pub(super) fn with_sections(&self, sections: Vec<SectionShown>) -> Self {
        Self {
            view: self.view,
            launch_record: self.launch_record,
            sections,
            notice: self.notice,
        }
    }
}

impl<'de> Deserialize<'de> for SandboxEvidence {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            view: Digest,
            launch_record: Digest,
            sections: Vec<SectionShown>,
            notice: String,
        }
        let wire = Wire::deserialize(deserializer)?;
        let order: Vec<SandboxSection> = wire.sections.iter().map(|shown| shown.section).collect();
        if order != SandboxSection::ALL {
            return Err(serde::de::Error::custom(
                "a sandbox view lists its four sections once each, in order",
            ));
        }
        if wire.notice != SANDBOX_NOTICE {
            return Err(serde::de::Error::custom(
                "a sandbox view carries its standing notice exactly",
            ));
        }
        Ok(Self {
            view: wire.view,
            launch_record: wire.launch_record,
            sections: wire.sections,
            notice: SANDBOX_NOTICE,
        })
    }
}
