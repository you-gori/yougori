//! What the realm asked a connector to do, written down before it is asked.
//!
//! The seam already guarantees that a connector which fails cannot corrupt a realm: nothing in it
//! is given a `Core` or a `Store`, so there is nothing it could write. That guarantee is correct
//! and it is exactly the problem this file exists for. When `apply` comes back `PartlyDone`, the
//! provider moved and the realm has no record that anything was even attempted. A hub restarted at
//! that moment has no idea somebody is seated at a desktop it never granted.
//!
//! So the realm writes a row before it asks, and settles it after the connector answers. The row
//! is the realm's, not the connector's: a connector never sees one, cannot write one and cannot
//! read one. What the row buys is that the worst case is a realm that says "we do not know", which
//! a person or the sweeper can act on, instead of a realm that believes something false.
//!
//! The states are a one-way street and the database enforces it rather than this code: the
//! triggers in schema version 8 refuse to change what was asked, refuse to re-settle a settled
//! row, refuse to lower the attempts and refuse to forget a row while a provider may still be out
//! of step with it. A second process, or a person with sqlite3, hits the same wall.
use super::Change;
use serde::{Deserialize, Serialize};

/// Where one connector task has got to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IntentState {
    /// Written before anything was sent. A hub that dies here has to assume the provider may have
    /// moved, because it cannot tell.
    Opened,
    /// The connector said it changed something.
    Done,
    /// The connector said nothing had to move.
    AlreadyTrue,
    /// The connector said no before anything moved.
    Refused,
    /// The connector changed something and then failed. The sweeper owns this row.
    Orphaned,
    /// The sweeper brought the provider back to what the realm decided.
    Reconciled,
    /// The sweeper undid it, because the realm no longer wants it.
    RolledBack,
    /// Nobody could settle it and a person has to look.
    Stuck,
}

impl IntentState {
    pub fn word(self) -> &'static str {
        match self {
            IntentState::Opened => "opened",
            IntentState::Done => "done",
            IntentState::AlreadyTrue => "alreadyTrue",
            IntentState::Refused => "refused",
            IntentState::Orphaned => "orphaned",
            IntentState::Reconciled => "reconciled",
            IntentState::RolledBack => "rolledBack",
            IntentState::Stuck => "stuck",
        }
    }

    pub fn parse(word: &str) -> Option<IntentState> {
        [
            IntentState::Opened,
            IntentState::Done,
            IntentState::AlreadyTrue,
            IntentState::Refused,
            IntentState::Orphaned,
            IntentState::Reconciled,
            IntentState::RolledBack,
            IntentState::Stuck,
        ]
        .into_iter()
        .find(|state| state.word() == word)
    }

    /// Which states may follow this one. Nothing goes backwards and a settled row stays settled.
    pub fn may_become(self, next: IntentState) -> bool {
        use IntentState::*;
        matches!(
            (self, next),
            (Opened, Done | AlreadyTrue | Refused | Orphaned | Stuck)
                | (Done, Reconciled | RolledBack | Stuck)
                | (Orphaned, Reconciled | RolledBack | Stuck)
                // A stuck row that is tried again and is still stuck stays stuck, with its
                // attempts raised. That is what the attempts column is for, and it is how the
                // sweeper knows to stop trying.
                | (Stuck, Reconciled | RolledBack | Stuck)
        )
    }

    /// Whether nothing more will happen to this row.
    pub fn settled(self) -> bool {
        matches!(self, IntentState::Refused | IntentState::AlreadyTrue | IntentState::Reconciled | IntentState::RolledBack)
    }

    /// Whether something at a provider may be out of step with this realm.
    pub fn needs_the_sweeper(self) -> bool {
        matches!(self, IntentState::Opened | IntentState::Done | IntentState::Orphaned | IntentState::Stuck)
    }

    /// What to show somebody, which never reads as an accusation and never claims to know more
    /// than the realm does.
    pub fn describe(self) -> &'static str {
        match self {
            IntentState::Opened => "asked for, with no answer yet",
            IntentState::Done => "the provider was changed",
            IntentState::AlreadyTrue => "nothing had to move",
            IntentState::Refused => "the provider said no, and nothing moved",
            IntentState::Orphaned => "something moved at the provider and the connector then failed",
            IntentState::Reconciled => "brought back into step with what this grid decided",
            IntentState::RolledBack => "undone, because this grid no longer wants it",
            IntentState::Stuck => "nobody could settle this, and a person has to look",
        }
    }
}

/// One thing the realm asked a connector to do.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Intent {
    pub id: String,
    pub realm_id: String,
    /// The registry row of the connector that was asked.
    pub connector: String,
    pub credential_id: String,
    pub destination: String,
    pub change: Change,
    pub subject_email: String,
    pub subject_name: String,
    pub target: String,
    /// `Plan::fingerprint` as it was when the task opened. A connector that would no longer make
    /// the same plan has a different fingerprint, and the sweeper refuses to carry out a plan it
    /// cannot reproduce.
    pub fingerprint: String,
    pub principal_id: String,
    pub device_id: String,
    pub workload_id: String,
    pub state: IntentState,
    pub attempts: u32,
    pub policy_version: u64,
    pub opened_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at: Option<i64>,
    /// How it ended, in the realm's words. Never a value: this goes through the same redaction
    /// gate every reason in a realm goes through.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
}

impl Intent {
    /// Whether this row and this plan are about the same thing. The sweeper re-plans and compares,
    /// because a connection whose settings changed since the task opened must never be fixed up
    /// blind: the plan it would make now is a different plan.
    pub fn is_the_same_plan(&self, plan: &super::Plan) -> bool {
        plan.fingerprint() == self.fingerprint && plan.connector() == self.connector
    }
}

/// How a connector task ended, in the realm's own words rather than the connector's.
///
/// A connector returns a sentence and a `Trouble`; this is what the realm decides that means, and
/// it is what the state machine moves on. Keeping them apart is deliberate: a connector's words go
/// into notes, and the realm's decision goes into the row.
#[derive(Clone, Debug)]
pub enum Ending {
    /// The provider was changed.
    Changed(String),
    /// Nothing had to move.
    AlreadyTrue(String),
    /// The provider said no, before anything moved.
    Refused(String),
    /// Something moved at the provider and then the connector failed. The one ending that leaves
    /// work behind, and the reason the sweeper exists.
    LeftBehind(String),
    /// The sweeper brought the provider back into step.
    Reconciled(String),
    /// The sweeper undid it.
    RolledBack(String),
    /// Nobody could settle it.
    Stuck(String),
}

impl Ending {
    pub fn state(&self) -> IntentState {
        match self {
            Ending::Changed(_) => IntentState::Done,
            Ending::AlreadyTrue(_) => IntentState::AlreadyTrue,
            Ending::Refused(_) => IntentState::Refused,
            Ending::LeftBehind(_) => IntentState::Orphaned,
            Ending::Reconciled(_) => IntentState::Reconciled,
            Ending::RolledBack(_) => IntentState::RolledBack,
            Ending::Stuck(_) => IntentState::Stuck,
        }
    }

    pub fn say(&self) -> &str {
        match self {
            Ending::Changed(said)
            | Ending::AlreadyTrue(said)
            | Ending::Refused(said)
            | Ending::LeftBehind(said)
            | Ending::Reconciled(said)
            | Ending::RolledBack(said)
            | Ending::Stuck(said) => said,
        }
    }

    /// What this ending is called in the audit, so one task reads as one thing in the history.
    pub fn action(&self) -> &'static str {
        match self {
            Ending::Changed(_) => "connector.task.done",
            Ending::AlreadyTrue(_) => "connector.task.already true",
            Ending::Refused(_) => "connector.task.refused",
            Ending::LeftBehind(_) => "connector.task.left behind",
            Ending::Reconciled(_) => "connector.task.reconciled",
            Ending::RolledBack(_) => "connector.task.rolled back",
            Ending::Stuck(_) => "connector.task.stuck",
        }
    }

    /// Whether the realm is recording something going wrong.
    pub fn decision(&self) -> crate::core::audit::Decision {
        use crate::core::audit::Decision;
        match self {
            Ending::Changed(_) | Ending::AlreadyTrue(_) | Ending::Reconciled(_) | Ending::RolledBack(_) => Decision::Allowed,
            Ending::Refused(_) | Ending::LeftBehind(_) | Ending::Stuck(_) => Decision::Refused,
        }
    }
}

/// Which way a connector task was read out of the realm's own decision, in a word the database
/// stores. `Change` has no serialisation of its own because nothing needed one until now.
pub fn change_word(change: Change) -> &'static str {
    match change {
        Change::Give => "give",
        Change::TakeBack => "takeBack",
    }
}

pub fn change_from(word: &str) -> Option<Change> {
    match word {
        "give" => Some(Change::Give),
        "takeBack" => Some(Change::TakeBack),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_connector_task_never_goes_backwards_and_a_settled_one_stays_settled() {
        use IntentState::*;
        // The only states a fresh row can reach are the ones a connector's answer produces.
        for next in [Done, AlreadyTrue, Refused, Orphaned, Stuck] {
            assert!(Opened.may_become(next), "{next:?}");
        }
        assert!(!Opened.may_become(Reconciled) && !Opened.may_become(RolledBack), "nothing is reconciled before it was attempted");

        // A row the sweeper owns can be put right or undone, and a row that was put right is done
        // with: re-settling one would let the sweeper act twice on one change.
        for settled in [Refused, AlreadyTrue, Reconciled, RolledBack] {
            assert!(settled.settled() && !settled.needs_the_sweeper());
            for next in [Opened, Done, Orphaned, Stuck, Reconciled] {
                assert!(!settled.may_become(next), "{settled:?} is settled and must not become {next:?}");
            }
        }
        for unsettled in [Opened, Done, Orphaned, Stuck] {
            assert!(!unsettled.settled() && unsettled.needs_the_sweeper(), "{unsettled:?} may still be out of step with a provider");
        }
        assert!(Stuck.may_become(Reconciled) && Stuck.may_become(RolledBack), "a person looking at a stuck row can still put it right");
        assert!(Stuck.may_become(Stuck), "and a row that was tried again and is still stuck stays stuck, with its attempts raised");
        assert!(!Stuck.may_become(Done) && !Stuck.may_become(AlreadyTrue), "and cannot be made to look as though it worked the first time");
    }

    #[test]
    fn every_state_and_every_change_survives_being_written_down_and_read_back() {
        for state in [IntentState::Opened, IntentState::Done, IntentState::AlreadyTrue, IntentState::Refused, IntentState::Orphaned, IntentState::Reconciled, IntentState::RolledBack, IntentState::Stuck] {
            assert_eq!(IntentState::parse(state.word()), Some(state));
            assert!(!state.describe().is_empty());
        }
        assert_eq!(IntentState::parse("whatever somebody typed"), None);
        for change in [Change::Give, Change::TakeBack] {
            assert_eq!(change_from(change_word(change)), Some(change));
        }
        assert_eq!(change_from("delete everything"), None);
    }

    #[test]
    fn an_ending_decides_the_state_and_the_words_the_history_keeps() {
        let endings = [
            Ending::Changed("moved".into()),
            Ending::AlreadyTrue("nothing to do".into()),
            Ending::Refused("the provider said no".into()),
            Ending::LeftBehind("seated and then failed".into()),
            Ending::Reconciled("put right".into()),
            Ending::RolledBack("undone".into()),
            Ending::Stuck("a person has to look".into()),
        ];
        for ending in &endings {
            assert!(ending.action().starts_with("connector.task."), "{}", ending.action());
            assert!(!ending.say().is_empty());
        }
        use crate::core::audit::Decision;
        assert_eq!(Ending::Changed("x".into()).decision(), Decision::Allowed);
        assert_eq!(Ending::LeftBehind("x".into()).decision(), Decision::Refused, "a provider that moved and then failed is not an allowed outcome");
        assert_eq!(Ending::Stuck("x".into()).state(), IntentState::Stuck);
    }
}
