//! The connection drill of VM-CP-29 (§17 line 3179; M08): what the host observed of deliberate
//! connection attempts between throwaway VM sandboxes a drill launched for the purpose and stopped
//! after (`sandbox_vm::drill`). Each attempt is judged from the host's own counters, never from
//! what a guest said: how many connections the connection gate refused or admitted during the
//! attempt, and how many times the callee's guest was asked to open the service's port. A guest
//! that made no attempt the host saw leaves its case undecided. Nothing here runs anything.

use std::collections::BTreeMap;

use serde::Serialize;

/// One case of the drill: who tries to reach what, under which grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillCase {
    /// A to B with no grant at either end.
    Ungranted,
    /// A to B's service under its grant: the granted port.
    Granted,
    /// A to B's other declared service, while A holds a grant to one.
    OtherService,
    /// A to B after the grant was withdrawn.
    Revoked,
    /// A to B after the grant expired.
    Expired,
    /// A to C while A holds a grant to B and B one to C.
    Transitive,
    /// B to C under its grant: the transitive case's control.
    TransitiveControl,
}

impl DrillCase {
    pub const ALL: [Self; 7] = [
        Self::Ungranted,
        Self::Granted,
        Self::OtherService,
        Self::Revoked,
        Self::Expired,
        Self::Transitive,
        Self::TransitiveControl,
    ];

    /// Whether the case's attempt must be refused.
    pub const fn refusal_expected(self) -> bool {
        !matches!(self, Self::Granted | Self::TransitiveControl)
    }
}

/// What the host observed during one attempt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct DrillAttempt {
    /// Connections of the caller the host refused: no grant reached, or the gate refused.
    pub refused: u64,
    /// Connections the gate admitted.
    pub admitted: u64,
    /// Times the callee's guest was asked to open the service's port.
    pub callee_opens: u64,
}

impl DrillAttempt {
    /// `Some(true)` when the attempt was refused with nothing asked of the callee, `Some(false)`
    /// when it reached the callee, `None` when the host saw no decision (the guest made no attempt
    /// it saw) or an admission that asked nothing of the callee.
    pub fn refused(&self) -> Option<bool> {
        match (self.refused, self.admitted, self.callee_opens) {
            (0, 0, 0) => None,
            (_, 0, 0) => Some(true),
            (_, _, opens) if opens > 0 => Some(false),
            _ => None,
        }
    }
}

/// The host's observations of one drill.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ConnectionDrill {
    pub attempts: BTreeMap<DrillCase, DrillAttempt>,
    /// Whether two of the drill's VMs shared host state: a private directory, or a writable volume
    /// of either; `None` when the host could not tell.
    pub shared_state: Option<bool>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_attempt_is_judged_from_the_hosts_counters_alone() {
        let attempt = |refused, admitted, callee_opens| DrillAttempt { refused, admitted, callee_opens }.refused();
        assert_eq!(attempt(1, 0, 0), Some(true), "refused, nothing asked of the callee");
        assert_eq!(attempt(0, 1, 1), Some(false), "admitted and the callee's port opened");
        assert_eq!(attempt(0, 0, 0), None, "no decision seen: the guest made no attempt");
        assert_eq!(attempt(1, 0, 1), Some(false), "a refusal after the callee was asked is no refusal");
        assert_eq!(attempt(0, 1, 0), None, "an admission that asked nothing of the callee decides nothing");
        assert!(DrillCase::Expired.refusal_expected() && !DrillCase::TransitiveControl.refusal_expected());
    }
}
