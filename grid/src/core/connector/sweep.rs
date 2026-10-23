//! Bringing a provider back into step with what the realm decided.
//!
//! This is where rollback actually lives, and it is worth saying why it has no generic form.
//! Undoing a plan is `revoke` of that same plan, which each connector implements by reversing the
//! change it was asked for; there is nothing a sweeper could do on a connector's behalf that the
//! connector does not already know how to do. What the sweeper adds is the deciding: which
//! direction, under what permission, and whether to act at all.
//!
//! The order below is the whole design, and each step is there because of one specific way this
//! goes wrong without it.
//!
//! A fresh permission is minted on every attempt, and the task's original permission is never
//! carried. That is what makes revocation bite: minting re-checks that the credential is live, the
//! account is not suspended, the computer is still in the realm, somebody still grants it and an
//! agreement still stands, all as of now rather than as of whenever the task opened.
//!
//! The plan is made again and its fingerprint compared with the one the row recorded. A connection
//! whose settings changed since the task opened would now make a different plan, and carrying out
//! a different plan because it has the same name is how one person ends up in a pool nobody chose.
//! A fingerprint that does not match means the row becomes stuck and nothing is sent.
//!
//! The direction comes from whether the realm still wants the change. When the permission cannot
//! be minted at all, the realm has withdrawn something, and the answer is to take the change back
//! rather than to put it right. That is the one case where a sweeper acts without a permission to
//! act with, and it does not: it records the row as stuck, because taking something back also
//! needs a credential and the realm has just refused to lend one.
use super::intent::{Ending, Intent, IntentState};
use super::limits::TRIES;
use super::{Change, Connector, Request, Subject, Ticket, Trouble};
use crate::core::identity::Action;
use crate::core::Core;
use std::collections::BTreeMap;

/// What one sweep did.
///
/// There is deliberately no count of what it undid. A sweep never undoes anything, and the reason
/// is worth stating rather than leaving a field at zero for ever: undoing a change needs a
/// credential, and the only signal this grid has that it should undo one is that the realm
/// withdrew that credential. Rollback is therefore a decision a person makes, through `roll_back`,
/// and not something a timer does.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Swept {
    /// Brought back to what the realm decided.
    pub reconciled: usize,
    /// Nobody could settle it and a person has to look.
    pub stuck: usize,
    /// Tasks left exactly as they were, because this computer does not hold their connector, or
    /// because nothing at all could be written about them. A hub that does not hold a connector
    /// knows nothing about what it did, and a realm whose database or permission check refused the
    /// write has recorded nothing to reason from either. One count, because what an administrator
    /// does about both is the same: look at the task, on a computer that can settle it.
    pub skipped: usize,
}

impl Swept {
    pub fn touched(&self) -> usize {
        self.reconciled + self.stuck
    }

    /// What to show an administrator, which never implies a provider was reached when it was not.
    pub fn describe(&self) -> String {
        if self.touched() == 0 && self.skipped == 0 {
            return "Every connector task in this grid is settled.".to_owned();
        }
        format!(
            "{} brought back into step, {} left for a person to look at, {} left untouched because this computer does not hold their connector or nothing could be written about them.",
            self.reconciled, self.stuck, self.skipped
        )
    }
}

/// Works through every task that may have left a provider out of step with this realm.
///
/// Connectors are taken by reference and by name, so this can be driven against a fixture in a
/// test with no provider anywhere. A task whose connector is not in the map is skipped and not
/// touched: a hub that does not hold the connector cannot re-plan the task, and settling a row it
/// cannot reproduce would be the realm deciding something on no evidence at all.
pub async fn sweep(core: &mut Core, by: &str, connectors: &BTreeMap<String, &dyn Connector>, now: i64) -> Result<Swept, String> {
    // Before anything is sent. Listing the tasks needs only the permission to read the history, and
    // that is all this asked for: everything below reaches the provider, and the permission to
    // spend a credential was not looked at until the row was written afterwards. A refusal that
    // arrives after somebody has been seated is a report, not a refusal.
    core.allowed(by, Action::ManageCredentials)?;
    let mut swept = Swept::default();
    for intent in core.unsettled_connector_tasks(by)? {
        let Some(connector) = connectors.get(&intent.connector) else {
            swept.skipped += 1;
            continue;
        };
        match settle_one(core, by, *connector, &intent, now).await {
            Ok(IntentState::Reconciled) => swept.reconciled += 1,
            Ok(_) => swept.stuck += 1,
            // Nothing could be written about this task at all. It is left exactly as it was, which
            // means the next sweep sees it again, which is the right answer for a realm whose
            // database would not take a change.
            Err(_) => swept.skipped += 1,
        }
    }
    Ok(swept)
}

/// One task, from the permission to the settled row.
async fn settle_one(core: &mut Core, by: &str, connector: &dyn Connector, intent: &Intent, now: i64) -> Result<IntentState, String> {
    if intent.attempts >= TRIES {
        if intent.state == IntentState::Stuck {
            return Ok(IntentState::Stuck);
        }
        let ending = Ending::Stuck(format!("this has been tried {} times and a person has to look at it", intent.attempts));
        return core.settle_connector_task(by, &intent.id, ending, &[], now).map(|settled| settled.state);
    }

    // A fresh permission, every time. Suspension, a withdrawn grant, a revoked computer and a
    // retired credential all bite here rather than at whatever moment the task first opened.
    let lent = core.use_credential(&intent.principal_id, &intent.device_id, &intent.workload_id, &intent.credential_id, "POST", "/", super::CHECKED_FOR, now);
    let token = match lent {
        Ok(token) => token,
        Err(said) => {
            // The realm has withdrawn something. The honest answer is that this grid can no longer
            // reach the provider to put anything right, in either direction, and the row says so
            // rather than claiming to have rolled anything back.
            let ending = Ending::Stuck(format!("this grid can no longer use that credential, so nothing can be put right or undone from here: {said}"));
            return core.settle_connector_task(by, &intent.id, ending, &connector.export_audit(), now).map(|settled| settled.state);
        }
    };
    let ticket = match Ticket::read(&token, now) {
        Ok(ticket) => ticket,
        Err(said) => return core.settle_connector_task(by, &intent.id, Ending::Stuck(said), &[], now).map(|settled| settled.state),
    };

    // The plan again, and it has to be the same plan. A connection whose settings changed since
    // the task opened makes a different plan now, and acting on one because it has the same name
    // is how somebody ends up in a pool nobody chose.
    let about = match Subject::new(&intent.subject_email, &intent.subject_name) {
        Ok(about) => about,
        Err(said) => return core.settle_connector_task(by, &intent.id, Ending::Stuck(said), &[], now).map(|settled| settled.state),
    };
    let plan = match connector.plan(&ticket, &Request::new(intent.change, about), now) {
        Ok(plan) => plan,
        Err(trouble) => {
            let ending = Ending::Stuck(format!("this connector would not make a plan for that task now: {}", trouble.say()));
            return core.settle_connector_task(by, &intent.id, ending, &connector.export_audit(), now).map(|settled| settled.state);
        }
    };
    if !intent.is_the_same_plan(&plan) {
        let ending = Ending::Stuck("this connection has changed since this task was asked for, so the plan it would carry out now is not the plan that was agreed. Somebody has to look at it.".to_owned());
        return core.settle_connector_task(by, &intent.id, ending, &connector.export_audit(), now).map(|settled| settled.state);
    }

    // A read-only connector has nothing to put right, and nothing to undo. It could not have
    // changed a provider in the first place, so a task of its that is unsettled is a task that was
    // opened and never carried out, and settling it as stuck is the truthful answer.
    if !connector.alters_anything() {
        let ending = Ending::Stuck(format!("{} only reads, so there is nothing at the provider for this grid to put right.", intent.connector));
        return core.settle_connector_task(by, &intent.id, ending, &connector.export_audit(), now).map(|settled| settled.state);
    }

    let checked = match connector.validate(&ticket, &plan, now).await {
        Ok(checked) => checked,
        Err(trouble) => {
            let ending = Ending::Stuck(format!("the provider would not answer, so this plan has not been checked and nothing was sent: {}", trouble.say()));
            return core.settle_connector_task(by, &intent.id, ending, &connector.export_audit(), now).map(|settled| settled.state);
        }
    };

    // Reconciling is doing the same thing again, which is safe because every connector behind
    // this seam either asks a provider that answers a change already made with a conflict, or
    // reads the provider first and sends nothing when nothing has to move.
    let outcome = connector.reconcile(&ticket, &plan, &checked, now).await;
    let notes = connector.export_audit();
    match outcome {
        Ok(outcome) => core.settle_connector_task(by, &intent.id, Ending::Reconciled(outcome.note), &notes, now).map(|settled| settled.state),
        Err(trouble) => {
            let ending = match &trouble {
                Trouble::PartlyDone(said) => Ending::Stuck(format!("the provider moved again and then failed, so this still needs a person: {said}")),
                other => Ending::Stuck(format!("this could not be put right: {}", other.say())),
            };
            core.settle_connector_task(by, &intent.id, ending, &notes, now).map(|settled| settled.state)
        }
    }
}

/// Undoing one task on purpose, which is rollback asked for rather than swept up.
///
/// An administrator who decides a change should never have been made calls this. It is the same
/// machinery the sweeper uses, with the direction decided by a person instead of by the realm's
/// own state, and it goes through `revoke` for the same reason: the connector knows how to undo
/// its own plan and nothing else does.
pub async fn roll_back(core: &mut Core, by: &str, connector: &dyn Connector, intent: &Intent, now: i64) -> Result<IntentState, String> {
    // Undoing moves a provider as surely as doing it did, so it is the same permission, asked for
    // in the same place: before the connector hears anything.
    core.allowed(by, Action::ManageCredentials)?;
    if !connector.alters_anything() {
        return Err(format!("{} only reads, so there is nothing of its to undo.", intent.connector));
    }
    let token = core.use_credential(&intent.principal_id, &intent.device_id, &intent.workload_id, &intent.credential_id, "POST", "/", super::CHECKED_FOR, now)?;
    let ticket = Ticket::read(&token, now)?;
    let about = Subject::new(&intent.subject_email, &intent.subject_name)?;
    let plan = connector.plan(&ticket, &Request::new(intent.change, about), now).map_err(|trouble| trouble.say().to_owned())?;
    if !intent.is_the_same_plan(&plan) {
        return Err("This connection has changed since this task was asked for, so what would be undone is not what was done. Somebody has to look at it.".to_owned());
    }
    let checked = connector.validate(&ticket, &plan, now).await.map_err(|trouble| trouble.say().to_owned())?;
    let outcome = connector.revoke(&ticket, &plan, &checked, now);
    let answer = outcome.await;
    let notes = connector.export_audit();
    match answer {
        Ok(outcome) => core.settle_connector_task(by, &intent.id, Ending::RolledBack(outcome.note), &notes, now).map(|settled| settled.state),
        Err(trouble) => {
            let ending = Ending::Stuck(format!("this could not be undone: {}", trouble.say()));
            core.settle_connector_task(by, &intent.id, ending, &notes, now)?;
            Err(trouble.say().to_owned())
        }
    }
}

/// Which way a compensating action goes, for a caller that wants to say it in words.
pub fn undoing(change: Change) -> Change {
    match change {
        Change::Give => Change::TakeBack,
        Change::TakeBack => Change::Give,
    }
}
