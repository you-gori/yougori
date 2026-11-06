//! The seams to other modules (rollout plan §15). The committed CORE-02 catalog (T05) is
//! read through [`CatalogObjects`], implemented here for its [`Catalog`], and the normal
//! loader that fresh and recovered jobs share (line 652) is a seam of its own. Progress
//! goes to the committed CORE-06 event hub (T10), and generations and leases come from
//! the committed CORE-04 coordinator (T09), both used directly.

use std::fmt;

use super::job::LoadRequest;
use crate::foundation::catalog::{Catalog, ObjectId, ObjectStatus, Scope};
use crate::foundation::ids::OperationId;

/// The catalog's view of an object, as restart reconciliation reads actual state
/// (T05). Resumable extents need no call here: the catalog's resumed import re-verifies
/// every staged extent before reusing it.
pub trait CatalogObjects {
    /// The object's status as its owner sees it.
    fn object_status(&self, owner: &Scope, object: ObjectId) -> Result<ObjectStatus, PortError>;
}

impl CatalogObjects for Catalog {
    fn object_status(&self, owner: &Scope, object: ObjectId) -> Result<ObjectStatus, PortError> {
        Ok(self.status(owner, object))
    }
}

/// The normal loader (line 652 "recover through the normal loader"): fresh jobs and jobs
/// recovered after a restart enter through the same `submit`, and nothing else restores
/// GPU state.
pub trait Loader {
    fn submit(&mut self, request: LoadRequest) -> Result<(), PortError>;

    fn cancel(&mut self, operation: &OperationId) -> Result<(), PortError>;
}

/// Which port failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PortName {
    Catalog,
    Loader,
}

/// How a port failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PortFailure {
    Unavailable,
    Refused,
}

/// A port call failed; the caller stops rather than assuming an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PortError {
    pub port: PortName,
    pub failure: PortFailure,
}

impl fmt::Display for PortError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let port = match self.port {
            PortName::Catalog => "the catalog",
            PortName::Loader => "the loader",
        };
        let failure = match self.failure {
            PortFailure::Unavailable => "is unavailable",
            PortFailure::Refused => "refused the call",
        };
        write!(f, "{port} {failure}")
    }
}

impl std::error::Error for PortError {}
