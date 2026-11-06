//! A view as shown at one moment (VM-W04 acceptance: "stale evidence not presented as
//! current"; CORE-07: UI and CLI resolve the same state).
//!
//! [`SandboxView::status_at`] labels every fact against one reading of the shared
//! evidence clock and the configuration fingerprint in force, and groups the facts into
//! the four fixed sections. The result is Serialize only: it is computed whenever a view
//! is shown and never stored, so the JSON a UI reads and the lines a CLI prints come from
//! the same labels and neither can outlive them.

use std::fmt;

use serde::Serialize;

use super::facts::FactValue;
use super::labels::FactLabel;
use super::record::{SandboxView, ViewNotice};
use super::sections::Section;
use crate::foundation::evidence::{ClockReading, ClockSession, ConfigurationFingerprint};
use crate::foundation::ids::{Digest, MonotonicTime};
use crate::sandbox_contract::declarations::ContractLine;

/// One fact with its label at the viewing time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ShownLine {
    pub fact: FactValue,
    pub label: FactLabel,
}

impl fmt::Display for ShownLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.fact, self.label)
    }
}

/// One section with its facts, in the view's order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ShownSection {
    pub section: Section,
    pub title: &'static str,
    pub lines: Vec<ShownLine>,
}

/// A view labelled at one moment under one configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ShownView {
    /// The digest of the stored view this was computed from.
    pub view: Digest,
    pub launch_record: Digest,
    pub contract: ContractLine,
    /// The clock session and time the labels were computed at.
    pub clock: ClockSession,
    pub shown_at: MonotonicTime,
    /// The configuration in force when the labels were computed.
    pub configuration: ConfigurationFingerprint,
    /// The four sections, in [`Section::ALL`] order, each listed even when empty.
    pub sections: Vec<ShownSection>,
    pub notice: ViewNotice,
}

impl ShownView {
    /// The lines of `section`.
    pub fn section(&self, section: Section) -> &[ShownLine] {
        self.sections
            .iter()
            .find(|shown| shown.section == section)
            .map_or(&[], |shown| shown.lines.as_slice())
    }

    /// Every line of every section, in order.
    pub fn lines(&self) -> impl Iterator<Item = &ShownLine> {
        self.sections
            .iter()
            .flat_map(|section| section.lines.iter())
    }

    /// Every line labelled unavailable now, wherever it is shown: stale or
    /// other-configuration evidence as well as capabilities the contract does not permit.
    pub fn unavailable(&self) -> impl Iterator<Item = &ShownLine> {
        self.lines().filter(|line| line.label.is_unavailable())
    }
}

impl SandboxView {
    /// Labels every fact at `now`, under `configuration`, the host configuration in force
    /// now, and groups the facts into the four sections. Host observations are judged
    /// against the view's freshness bound, the launch's evidence requirement.
    pub fn status_at(
        &self,
        now: ClockReading,
        configuration: ConfigurationFingerprint,
    ) -> ShownView {
        let body = self.body();
        let sections = Section::ALL
            .into_iter()
            .map(|section| ShownSection {
                section,
                title: section.title(),
                lines: body
                    .facts
                    .iter()
                    .filter(|fact| fact.section() == section)
                    .map(|fact| ShownLine {
                        fact: fact.value.clone(),
                        label: fact.label_at(now, configuration, body.max_age),
                    })
                    .collect(),
            })
            .collect();
        ShownView {
            view: self.digest(),
            launch_record: body.launch_record,
            contract: body.contract,
            clock: now.session(),
            shown_at: now.at(),
            configuration,
            sections,
            notice: ViewNotice,
        }
    }
}
