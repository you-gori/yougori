//! What a realm can say about itself, taken from its own database and from nothing else.
//!
//! Every number here is a count or an age, and every one of them comes from a statement written in
//! this file. None of them is a prompt, an answer, a file, a secret, a person's name or a path.
//! The one string a reading carries is a model plan's identifier and the model's name, which an
//! administrator typed into a plan and which the product already shows.
//!
//! Where a number is narrower than it looks, the struct says so rather than the document saying it
//! somewhere else. Three of them are worth knowing before reading any of this:
//!
//!   * computers heard from recently counts computers that have authenticated, because that is the
//!     only thing that writes the time. A computer that is on and idle and never authenticates is
//!     not counted, and a realm that no profile authenticates against reports nought.
//!   * model readiness from the database is placement: which plan the realm put on which computer.
//!     Whether a model is actually loaded changes every few seconds, and writing that into a
//!     realm's database would turn it into a telemetry store.
//!   * a count of refusals over a window is capped by how far the history still reaches, because
//!     the chain is trimmed once it has been exported. `reaches` says where the cap is.
//!
//! Nothing here binds a port. A reading is a value the product serialises; whether there is an
//! endpoint is a decision for whatever opens the realm.
use super::store::{Counts, Store};
use super::work::Stage;
use super::{realm::Capability, workspace, Core};
use serde::Serialize;

/// The window a reading reports rates over, unless the caller asks for another: one hour.
pub const WINDOW: i64 = 60 * 60;

/// How recently a computer must have been heard from to be counted as here.
///
/// The shipped hub's own window (`hub::ONLINE`), so the core and the hub mean the same thing by
/// a computer being about.
pub const HEARD_FROM_WITHIN: i64 = 75;

/// How much work is waiting, and at which stage.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueDepth {
    pub queued: usize,
    pub leased: usize,
    pub preparing: usize,
    pub running: usize,
    pub draining: usize,
}

impl QueueDepth {
    pub fn total(&self) -> usize {
        self.queued + self.leased + self.preparing + self.running + self.draining
    }
}

/// How many computers there are, and how many of them could take work.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HostAvailability {
    pub offering: usize,
    pub taking_work: usize,
    /// Computers that have authenticated within `HEARD_FROM_WITHIN`. See the note at the top of
    /// this file: nothing else writes that time.
    pub heard_from_recently: usize,
}

/// What the realm decided about models, and what a runner saw, kept apart.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ModelReadiness {
    /// From the database: each plan, the model it serves, and how many computers hold it.
    pub placed: Vec<(String, String, usize)>,
    /// From whatever runs the models, when there is anything to say. `None` means nobody has
    /// reported, which is not the same as nothing being loaded.
    pub reported: Option<Vec<(String, usize)>>,
}

/// How workspaces are going.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceHealth {
    pub failed: usize,
    /// Ordered, and still without a computer since before the window asked for opened. How far
    /// the history reaches does not cut this one: nothing trims `workspaces`, so the window it
    /// answers is the window the caller asked for.
    pub waiting_for_a_computer: usize,
    /// For the life of the realm, not over the window.
    pub placement_attempts: usize,
    /// The same: a total for the life of the realm.
    pub rebuilds: usize,
    /// Packed copies no computer has taken for longer than `workspace::PARCEL_PATIENCE`.
    pub stuck_parcels: usize,
}

/// How long agreement is taking.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ApprovalLatency {
    pub waiting: usize,
    /// How long the oldest unanswered request has waited, in seconds.
    pub oldest_wait: i64,
    pub decided_in_window: usize,
    /// The mean time from asking to being answered over the window, in seconds.
    pub average_wait: i64,
}

/// What went wrong with credentials, as the realm wrote it down.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CredentialFailures {
    /// Events in the window about credentials whose decision was a refusal.
    pub refused_in_window: usize,
    pub due_to_rotate: usize,
    pub brokered_requests_held: usize,
}

/// What an authorised research realm has found. A research realm is a `Core` of its own with its
/// own database, so its reading is taken the same way and never joined to the company's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchFindings {
    pub scopes_open: usize,
    pub findings: usize,
    pub awaiting_review: usize,
}

/// One reading of one realm.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reading {
    pub at: i64,
    /// The window the rates below are over, in seconds.
    pub window: i64,
    /// How far back the sealed history actually reaches. A window longer than this cannot be
    /// answered honestly, so `window` is capped at it and this says where the cap came from.
    pub reaches: i64,
    pub counts: Counts,
    pub queue: QueueDepth,
    /// How old the oldest reservation still holding room is, in seconds.
    pub oldest_lease_age: i64,
    pub live_leases: usize,
    pub hosts: HostAvailability,
    pub models: ModelReadiness,
    pub workspaces: WorkspaceHealth,
    pub approvals: ApprovalLatency,
    pub credentials: CredentialFailures,
    pub research: ResearchFindings,
    /// Events the history holds, and how many of them have never left this computer.
    pub audit_events: usize,
    pub audit_events_never_exported: usize,
}

impl Core {
    /// One reading over the last hour.
    pub fn reading(&self, now: i64) -> Result<Reading, String> {
        self.reading_over(WINDOW, now)
    }

    /// One reading over a window of the caller's choosing.
    ///
    /// Every statement behind this is a count or an aggregate written against the indexes schema
    /// version 10 added, and all but one of them gives back a single row; the exception is the
    /// grouped statement behind model readiness, which gives back a row per model plan and is
    /// therefore capped by `model::MAX_PLANS`. What that means and what it does not: the number of
    /// statements and the number of rows handed back do not grow with how much the realm holds,
    /// which is what `a_reading_costs_the_same_whatever_the_grid_holds` measures. It is not a
    /// claim that the time does not grow, because the time a count takes grows with the table it
    /// counts, and nothing here has measured one at the sizes the limits table warns at. Nor does
    /// it say whether the numbers mean what an operator hopes: see the notes at the top of this
    /// file.
    pub fn reading_over(&self, window: i64, now: i64) -> Result<Reading, String> {
        reading_over(&self.store, self.realm.can(Capability::Research), window, now)
    }
}

/// One reading of a realm's database, with whether it is a research realm passed in.
///
/// It takes a store rather than a `Core` for the same reason `health::checkup` does: something
/// serving a reading to a monitoring agent has to be able to answer for a realm it opened
/// read-only, because opening one the ordinary way brings it up to this build's shape, and that is
/// a write nobody asked for. Whether the realm does research is passed in rather than read here,
/// so that this stays the twelve statements the operations document says it is.
pub fn reading_over(store: &Store, research: bool, window: i64, now: i64) -> Result<Reading, String> {
    let (held, reaches, never_exported) = store.history_shape()?;
    let asked = window.max(0);
    // A window longer than the history reaches would report fewer refusals than happened and
    // look like good news. It is cut to what the chain still holds instead.
    let window = if reaches > 0 { asked.min((now - reaches).max(0)) } else { 0 };
    let since = now - window;

    let mut queue = QueueDepth::default();
    for (stage, count) in store.queue_depth()? {
        match stage {
            Stage::Queued => queue.queued = count,
            Stage::Leased => queue.leased = count,
            Stage::Preparing => queue.preparing = count,
            Stage::Running => queue.running = count,
            Stage::Draining => queue.draining = count,
            _ => {}
        }
    }

    let (live_leases, oldest_lease_age) = store.live_lease_age(now)?;
    let (offering, taking_work, heard_from_recently) = store.host_availability(now - HEARD_FROM_WITHIN)?;
    // This one answers the window that was asked for rather than the cut one. The cut exists
    // for the refusal count, which comes out of the history and cannot honestly reach past
    // where the history stops. Nothing trims `workspaces`. Cutting this to the chain would
    // turn a young realm, a trim, or the hour after a desks migration that carries each desk's
    // own time, into a pile of workspaces that look as though they had waited out the window.
    let (failed, waiting_for_a_computer, placement_attempts, rebuilds) = store.workspace_states(now - asked)?;
    let (waiting, oldest_wait) = store.waiting_requests(now)?;
    let (decided_in_window, average_wait) = store.decided_since(since)?;
    let counts = store.counts()?;

    Ok(Reading {
        at: now,
        window,
        reaches,
        queue,
        live_leases,
        oldest_lease_age,
        hosts: HostAvailability { offering, taking_work, heard_from_recently },
        models: ModelReadiness { placed: store.plan_placements()?, reported: None },
        workspaces: WorkspaceHealth {
            failed,
            waiting_for_a_computer,
            placement_attempts,
            rebuilds,
            stuck_parcels: store.count_stuck_artifacts(now - workspace::PARCEL_PATIENCE)?,
        },
        approvals: ApprovalLatency { waiting, oldest_wait, decided_in_window, average_wait },
        credentials: CredentialFailures {
            refused_in_window: store.refusals_since(Capability::Credentials, since)?,
            due_to_rotate: store.credentials_due_to_rotate(now)?,
            brokered_requests_held: counts.credential_uses,
        },
        research: research_reading(store, research)?,
        audit_events: held,
        audit_events_never_exported: never_exported,
        counts,
    })
}
/// What an authorised research realm has found, and nought in a realm that does no research.
fn research_reading(store: &Store, research: bool) -> Result<ResearchFindings, String> {
    if !research {
        return Ok(ResearchFindings::default());
    }
    let (scopes_open, findings, awaiting_review) = store.research_shape()?;
    Ok(ResearchFindings { scopes_open, findings, awaiting_review })
}

#[cfg(test)]
mod tests;
