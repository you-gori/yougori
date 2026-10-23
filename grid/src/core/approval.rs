//! Asking someone else to agree.
//!
//! Some things are not done on one person's say-so: using a company credential, and admitting
//! source and people to a research realm. The person who asks is not the person who agrees, for
//! as long as there is anyone else who could. Where a realm has exactly one person who can
//! decide, that person may decide their own request — a grid of one is not stuck — and it is
//! recorded as self-issued rather than passed off as someone else's agreement.
//!
//! An approver may agree to one request, or allow the same narrow thing for a few hours. Some
//! requests are never covered by a standing allowance and need an approver every time.
use super::identity::{Action, Principal, Role};
use serde::{Deserialize, Serialize};

/// How long a request waits for an answer before it lapses.
pub const WAIT: i64 = 15 * 60;
/// The longest a standing allowance may last.
pub const MAX_HOURS: u32 = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum State {
    Waiting,
    Granted,
    Refused,
    Expired,
}

/// What an approver decided.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Agree to this request alone.
    Once,
    /// Agree, and allow the same narrow thing for this many hours.
    Hours(u32),
    /// Refuse, with a reason the asker can read.
    Denied(String),
}

/// One request for someone else's agreement.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub id: String,
    pub realm_id: String,
    /// What is being asked for.
    pub action: String,
    /// What it is about: a credential, a research scope.
    pub resource_id: String,
    /// The narrow thing being asked, when the request is about reaching something.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    pub requested_by: String,
    pub requested_at: i64,
    pub expires_at: i64,
    /// This kind of request always needs an approver; no standing allowance covers it.
    #[serde(default)]
    pub every_time: bool,
    pub state: State,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<i64>,
    /// True when the requester decided it themselves because nobody else could.
    #[serde(default)]
    pub self_issued: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reason: String,
}

impl Approval {
    pub fn request(realm_id: &str, action: Action, resource_id: &str, requested_by: &str, every_time: bool, now: i64, seconds: i64) -> Approval {
        Approval {
            id: format!("approval-{}", &crate::token()[..16]),
            realm_id: realm_id.to_owned(),
            action: action.name().to_owned(),
            resource_id: resource_id.to_owned(),
            method: None,
            path: None,
            requested_by: requested_by.to_owned(),
            requested_at: now,
            expires_at: now + seconds.clamp(60, 30 * 24 * 60 * 60),
            every_time,
            state: State::Waiting,
            decided_by: None,
            decided_at: None,
            self_issued: false,
            reason: String::new(),
        }
    }

    /// Narrows the request to one way of reaching one thing.
    pub fn about(mut self, method: &str, path: &str) -> Approval {
        self.method = Some(method.to_ascii_uppercase());
        self.path = Some(path.to_owned());
        self
    }

    /// Whether this approval still allows the thing it was asked for.
    pub fn stands(&self, now: i64) -> bool {
        self.state == State::Granted && now < self.expires_at
    }

    /// Whether this is a request to do `action`, asked where whoever spends it is about to act.
    ///
    /// `decide` already holds an approver to the action their request names, which keeps the two
    /// approver populations apart at the moment somebody agrees. This is the other half, and it
    /// belongs wherever an agreement is spent: the requester is the one who chooses the action,
    /// and the thing a request names may not even exist yet when it is asked, so the moment of use
    /// is the only moment at which the action and what it is being spent on are both known. An
    /// agreement to approve research is not an agreement to send a company credential, however it
    /// is presented afterwards.
    pub fn asked_to(&self, action: Action) -> bool {
        self.action == action.name()
    }
}

/// An approver's standing agreement to the same narrow thing for a while: this person, this
/// resource, this method and this path, until it runs out.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Allowance {
    pub id: String,
    pub realm_id: String,
    pub principal_id: String,
    pub resource_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The request this came from, and who agreed to it.
    pub approval_id: String,
    pub approved_by: String,
    pub granted_at: i64,
    pub expires_at: i64,
}

impl Allowance {
    /// Whether this allowance covers what is being asked for now. An allowance with a method or
    /// path covers only that one.
    pub fn covers(&self, principal_id: &str, resource_id: &str, method: Option<&str>, path: Option<&str>, now: i64) -> bool {
        now < self.expires_at
            && self.principal_id == principal_id
            && self.resource_id == resource_id
            && self.method.as_deref().is_none_or(|allowed| method.map(str::to_ascii_uppercase).as_deref() == Some(allowed))
            && self.path.as_deref().is_none_or(|allowed| path == Some(allowed))
    }

    /// What to show beside it, naming who agreed and to what.
    pub fn describe(&self) -> String {
        format!(
            "allowed by {} until {}, from request {}",
            self.approved_by,
            self.expires_at,
            self.approval_id
        )
    }
}

/// Who else could decide this, other than the person who asked.
pub fn other_approvers<'a>(people: &'a [Principal], action: Action, requested_by: &str) -> Vec<&'a Principal> {
    people.iter().filter(|person| person.id != requested_by && person.may(action)).collect()
}

/// Which permissions let somebody decide this, read off the roles themselves rather than written
/// out at a call site.
///
/// The same question `other_approvers` asks of a list of people, in the one form a database can be
/// asked it: a realm with five hundred accounts should not have to build all five hundred, with
/// another query each to fill in what they hold, to find out whether anybody but the requester
/// could agree. Being derived from `Role::may` rather than listed means a new role that may
/// approve something is counted here the day it is written.
pub fn approving_roles(action: Action) -> Vec<Role> {
    Role::every().iter().copied().filter(|role| role.may(action)).collect()
}

/// `decide`, where the caller has already established whether the requester is the only person
/// who could agree.
///
/// This exists because that one fact is the only thing `decide` wanted the realm's whole
/// population for. Suspended accounts have never counted towards it: `Principal::may` is
/// `active() && any role may`, and whatever answers this question has to keep that true.
pub fn decide_knowing(
    approval: &mut Approval,
    action: Action,
    approver: &Principal,
    alone: bool,
    verdict: Verdict,
    now: i64,
) -> Result<Option<Allowance>, String> {
    decide_inner(approval, action, approver, alone, verdict, now)
}

/// Records a decision, and the standing allowance it creates when there is one.
///
/// Someone other than the requester must decide while anyone else can. Where the realm has only
/// one person who can decide, that person may decide their own request and it is marked
/// self-issued. A request that must have an approver every time never becomes an allowance.
///
/// The request is decided under the action it was asked for, never one the decider names. Both
/// rules below are read off that action: which permission an approver has to hold, and who else
/// could have decided instead. Approving a credential and approving research are separate
/// permissions on purpose, so a decider free to choose between them could agree to a credential
/// while holding only the research permission, or name an action nobody else in the realm holds
/// and so become the only possible approver of their own request.
pub fn decide(
    approval: &mut Approval,
    action: Action,
    approver: &Principal,
    people: &[Principal],
    verdict: Verdict,
    now: i64,
) -> Result<Option<Allowance>, String> {
    let alone = other_approvers(people, action, &approval.requested_by).is_empty();
    decide_inner(approval, action, approver, alone, verdict, now)
}

fn decide_inner(
    approval: &mut Approval,
    action: Action,
    approver: &Principal,
    alone: bool,
    verdict: Verdict,
    now: i64,
) -> Result<Option<Allowance>, String> {
    if approval.state != State::Waiting {
        return Err("This request was already decided".into());
    }
    if now >= approval.expires_at {
        approval.state = State::Expired;
        return Err("This request expired before it was decided".into());
    }
    if approval.action != action.name() {
        return Err(format!("That request asks to {}, and it is decided as that and not as {}", approval.action, action.name()));
    }
    if !approver.may(action) {
        return Err(format!("{} may not {}", approver.name, action.name()));
    }
    if approver.id == approval.requested_by && !alone {
        return Err("Someone else must agree to this; ask one of the other approvers".into());
    }
    if let Verdict::Hours(hours) = &verdict {
        if approval.every_time {
            return Err("This kind of request needs an approver every time; it cannot be allowed in advance".into());
        }
        if *hours == 0 || *hours > MAX_HOURS {
            return Err(format!("Allow it for 1 to {MAX_HOURS} hours"));
        }
    }
    approval.decided_by = Some(approver.id.clone());
    approval.decided_at = Some(now);
    approval.self_issued = approver.id == approval.requested_by;
    match verdict {
        Verdict::Denied(reason) => {
            approval.state = State::Refused;
            approval.reason = reason.chars().filter(|c| !c.is_control()).take(500).collect();
            Ok(None)
        }
        Verdict::Once => {
            approval.state = State::Granted;
            Ok(None)
        }
        Verdict::Hours(hours) => {
            approval.state = State::Granted;
            Ok(Some(Allowance {
                id: format!("allowance-{}", &crate::token()[..16]),
                realm_id: approval.realm_id.clone(),
                principal_id: approval.requested_by.clone(),
                resource_id: approval.resource_id.clone(),
                method: approval.method.clone(),
                path: approval.path.clone(),
                approval_id: approval.id.clone(),
                approved_by: approver.id.clone(),
                granted_at: now,
                expires_at: now + i64::from(hours) * 3_600,
            }))
        }
    }
}
