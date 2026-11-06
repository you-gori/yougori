//! Permissions and grants as shown to the user (S2 CORE-07 "permissions"; VM-W53: "what it
//! can read/release"; VM-P46: approvals users can tell apart).
//!
//! Two existing sources say what a setup may do. The setup crate's capability registry
//! names the permissions a capability asks for, in plain words for the plan review, and
//! says that enabling a capability does not grant them. V17's view of a launched sandbox
//! lists what its resolved contract permits, the approvals it needs and the requested
//! capabilities the contract does not permit. A [`PermissionLine`] shows either one with
//! its [`PermissionStatus`]: asking is never granting, and a contract's permission states
//! what is allowed, never that anything enforces it. The engine's `product_views` module
//! converts both sources into these lines.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize};

use super::refusal::Refusal;
use super::text::ShownText;
use crate::foundation::ids::{validate_identifier, IdError};

strict_product_enum! {
    /// Where a permission stands.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum PermissionStatus tag "status" {
        /// Asked for by a capability or declaration; asking grants nothing, and the engine
        /// checks it again at use time.
        Requested,
        /// The resolved contract permits it: a statement of what is allowed, not that
        /// anything enforces it.
        PermittedByContract,
        /// It needs an approval that has not been given.
        AwaitingApproval,
        /// A valid approval covers it for this authorization epoch.
        Approved,
        /// The contract does not permit it.
        NotPermitted { refusal: Refusal },
    }
}

impl fmt::Display for PermissionStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Requested => f.write_str("requested; asking does not grant it"),
            Self::PermittedByContract => f.write_str(
                "permitted by the contract; this states what is allowed, not that anything \
                 enforces it",
            ),
            Self::AwaitingApproval => f.write_str("needs your approval"),
            Self::Approved => f.write_str("approved for this authorization"),
            Self::NotPermitted { refusal } => write!(f, "not permitted: {refusal}"),
        }
    }
}

/// One permission as shown: its kind (a setup permission id, or V17's fact tag), its
/// wording and its status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PermissionLine {
    kind: String,
    text: ShownText,
    status: PermissionStatus,
}

impl PermissionLine {
    /// A permission of `kind`, a fixed identifier of the source's vocabulary (a setup
    /// permission id or V17's fact tag), worded `text`, in `status`.
    /// [`PermissionLine::check`] checks the kind's grammar.
    pub fn new(kind: &'static str, text: &str, status: PermissionStatus) -> Self {
        Self {
            kind: kind.to_owned(),
            text: ShownText::new(text),
            status,
        }
    }

    pub fn kind(&self) -> &str {
        &self.kind
    }

    pub fn text(&self) -> &ShownText {
        &self.text
    }

    pub fn status(&self) -> &PermissionStatus {
        &self.status
    }

    /// The kind follows the ids.rs identifier grammar.
    pub fn check(&self) -> Result<(), IdError> {
        validate_identifier(&self.kind)
    }
}

impl fmt::Display for PermissionLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.text, self.status)
    }
}

impl<'de> Deserialize<'de> for PermissionLine {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            kind: String,
            text: ShownText,
            status: PermissionStatus,
        }
        let wire = Wire::deserialize(deserializer)?;
        let line = Self {
            kind: wire.kind,
            text: wire.text,
            status: wire.status,
        };
        line.check().map_err(serde::de::Error::custom)?;
        Ok(line)
    }
}
