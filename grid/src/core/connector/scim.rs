//! People and group membership over SCIM 2.0.
//!
//! This is the one standard in this phase that fits the trait without being bent. A SCIM server
//! knows a person by `userName`, which for every deployment worth supporting is their email, and
//! what it offers is membership of a group. Give and take back are exactly a `PatchOp` with `add`
//! and one with `remove`, and both of them are about one named person at one target, which is what
//! `Request` already says.
//!
//! Only the client direction is here. A SCIM *server*, which is the company's own directory
//! pushing people at us, is not a connector at all: nothing about it is discovered, planned or
//! revoked by this grid, and it would be a profile with a door of its own.
//!
//! Three things about carrying this out are worth saying before the code.
//!
//! The group is read before it is changed, so `Outcome.already` is what the server says rather
//! than what this connector remembers. RFC 7644 does not say what a server answers when a member
//! that is already there is added again: some answer 204, some answer 409. Reading first means
//! this connector reports the same thing whichever kind of server it is talking to, and it is why
//! applying a plan twice is safe here. A server may also return the group without its members, and
//! then reading rules nothing out: the change is sent, and the server's own answer to it decides.
//!
//! The filter is built with the person's email in it, which means the email is escaped and checked
//! before it goes into a query. `Subject::new` has already refused control characters and
//! whitespace; what is left to refuse is a quote and a backslash, which would end the filter early.
//!
//! Nothing here has met a real directory. It is exercised against a server on this computer that
//! answers the way RFC 7644 describes, which proves the shape of each request and the order of the
//! calls, and proves nothing at all about Okta, Entra ID or anybody else's implementation.
use super::wire::{Call, Reply, Wire};
use super::{admits, cleared, Answer, Change, Checked, Connector, Discovery, Found, Note, Notes, Outcome, Plan, Rehearsal, Request, Seen, Settings, Step, Subject, Ticket, Trouble};
use crate::core::audit::Decision;
use serde_json::{json, Value};

/// The registry row this is.
pub const ROW: &str = "SCIM 2.0";

/// The message schema a patch has to name. Written down once because getting it wrong is the
/// commonest way a SCIM patch is rejected, and a constant is easier to check than a literal in
/// three places.
pub const PATCH_OP: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";

/// A SCIM 2.0 client, pointed at one group.
pub struct Scim {
    settings: Settings,
    wire: Box<dyn Wire>,
    notes: Notes,
}

impl std::fmt::Debug for Scim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("Scim").field("destination", &self.wire.destination()).field("settings", &self.settings.names()).finish()
    }
}

/// A `userName` as it goes inside a SCIM filter.
///
/// A filter is a little language with quoted strings in it, so a quote or a backslash in the value
/// would end the string early and the rest would be read as more filter. `Subject::new` has
/// already refused whitespace and control characters; this refuses the two that are left rather
/// than escaping them, because an email address with a quote in it is not an address anybody has.
fn in_a_filter(email: &str) -> Result<&str, Trouble> {
    if email.contains('"') || email.contains('\\') {
        return Err(Trouble::Missing("This address has a quote in it, which a directory filter cannot carry. Correct the address and try again.".into()));
    }
    Ok(email)
}

impl Scim {
    pub fn new(settings: Settings, wire: Box<dyn Wire>) -> Scim {
        Scim { settings, wire, notes: Notes::new() }
    }

    fn complete(&self) -> Result<(), Trouble> {
        self.settings.needed("group", "group")?;
        Ok(())
    }

    fn group(&self) -> Result<&str, Trouble> {
        self.settings.needed("group", "group")
    }

    fn record(&self, at: i64, action: &str, decision: Decision, reason: &str) {
        self.notes.keep(Note::new(ROW, at, action, decision, reason));
    }

    /// A note with which version of the credential authorised the request it describes.
    fn with_version(&self, said: &str) -> String {
        match self.wire.version_used() {
            Some(version) => format!("{said} (credential version {version})"),
            None => said.to_owned(),
        }
    }

    async fn ask(&self, ticket: &Ticket, call: Call, action: &str, now: i64) -> Result<Reply, Trouble> {
        match self.wire.send(ticket, call, now).await {
            Ok(reply) if reply.ok() => {
                self.record(now, action, Decision::Allowed, &self.with_version(&reply.said()));
                Ok(reply)
            }
            Ok(reply) => {
                let said = reply.said();
                self.record(now, action, Decision::Refused, &said);
                Err(Trouble::Refused(said))
            }
            Err(trouble) => {
                self.record(now, action, Decision::Refused, trouble.say());
                Err(trouble)
            }
        }
    }

    /// The group as the server holds it now.
    async fn read_group(&self, ticket: &Ticket, action: &str, now: i64) -> Result<Value, Trouble> {
        let reply = self.ask(ticket, Call::get(&format!("/Groups/{}", self.group()?)), action, now).await?;
        Ok(reply.json())
    }

    /// The person's identifier at this directory, found by the one thing a SCIM server knows them
    /// by. A directory that does not have them is a `Missing`, not a refusal, because nothing was
    /// wrong with the request.
    async fn find(&self, ticket: &Ticket, about: &Subject, action: &str, now: i64) -> Result<String, Trouble> {
        let filter = format!("userName eq \"{}\"", in_a_filter(about.email())?);
        let reply = self.ask(ticket, Call::get("/Users").with("filter", &filter).with("count", "2"), action, now).await?;
        let body = reply.json();
        // RFC 7644 lets a list answer leave `Resources` out only when it found nobody, and then it
        // says so with `totalResults` 0. An answer with neither, such as a proxy's page or a broken
        // body, was not read, and taking it for nobody told an admin that the person was not in the
        // directory while they kept their account there. The same goes for an empty list that
        // says it holds somebody.
        let unread = || Trouble::Refused(format!("The directory's answer to a search for {} could not be read as a list of people, so nothing was changed. Try again; if it keeps happening, check the directory's SCIM address.", about.email()));
        let found: Vec<&Value> = match (body["Resources"].as_array(), body["totalResults"].as_u64()) {
            (Some(rows), Some(total)) if rows.is_empty() && total > 0 => return Err(unread()),
            (Some(rows), _) => rows.iter().collect(),
            (None, Some(0)) => Vec::new(),
            (None, _) => return Err(unread()),
        };
        match found.as_slice() {
            [] => Err(Trouble::Missing(format!("{} is not in this directory, so there is nobody to change.", about.email()))),
            [one] => one["id"].as_str().map(str::to_owned).ok_or_else(|| Trouble::Refused("The directory answered with a person who has no identifier".to_owned())),
            _ => Err(Trouble::Refused(format!("This directory has more than one account with the address {}, and this grid will not guess which one was meant.", about.email()))),
        }
    }

    /// Whether this person is in the group the connection names, from the group as it is now, or
    /// nothing when the answer does not list the group's members.
    ///
    /// A server may leave `members` out of a group it returns: RFC 7643 leaves an unassigned
    /// attribute out, and a server may return only some attributes. A group answered without the
    /// list is a group whose members were not said, never a group with none. Read as empty, a
    /// take-back found the person "already out", sent nothing and reported the removal done while
    /// they kept the group.
    fn member_of(group: &Value, user_id: &str) -> Option<bool> {
        let members = group["members"].as_array()?;
        Some(members.iter().any(|member| member["value"].as_str() == Some(user_id)))
    }

    /// What is said when the group's members could not be read.
    fn unlisted(plan: &Plan) -> String {
        format!("The directory does not list the members of {}, so whether {} is in it cannot be read", plan.target(), plan.about().email())
    }

    /// The patch that gives somebody the group, or takes it back.
    ///
    /// `add` names the path and carries the member; `remove` names the member in the path, which
    /// is how RFC 7644 section 3.5.2 says one member is taken out rather than the whole attribute.
    fn patch(change: Change, user_id: &str) -> Value {
        match change {
            Change::Give => json!({"schemas": [PATCH_OP], "Operations": [{"op": "add", "path": "members", "value": [{"value": user_id}]}]}),
            Change::TakeBack => json!({"schemas": [PATCH_OP], "Operations": [{"op": "remove", "path": format!("members[value eq \"{user_id}\"]")}]}),
        }
    }

    fn fits(&self, ticket: &Ticket, plan: &Plan, now: i64) -> Result<(), Trouble> {
        admits(ticket, self.wire.destination(), now)?;
        self.complete()?;
        if plan.connector() != ROW {
            return Err(Trouble::NotAllowed(format!("This plan is for {}, and this connector is {ROW}", plan.connector())));
        }
        if plan.credential_id() != ticket.credential_id() {
            return Err(Trouble::NotAllowed("This plan was made for another credential. Make it again with the permission you hold.".into()));
        }
        Ok(())
    }

    /// The whole of carrying a plan out, whichever way round it goes.
    ///
    /// The group is read first, so what is reported as already true is what the server says.
    /// Nothing is sent when nothing has to move, which is what makes doing this twice free, and it
    /// is also the one thing that keeps a directory that counts its writes from counting two.
    ///
    /// When the group comes back without its members, nothing can be ruled out by reading, so the
    /// change is sent and the directory's answer to it is believed instead: a conflict says an add
    /// was already so, and `noTarget` says a removal matched nobody (RFC 7644 section 3.5.2).
    async fn move_one(&self, ticket: &Ticket, plan: &Plan, change: Change, action: &str, now: i64) -> Result<Outcome, Trouble> {
        let user_id = self.find(ticket, plan.about(), action, now).await?;
        let group = self.read_group(ticket, action, now).await?;
        let wanted = change == Change::Give;
        let way = if wanted { "in" } else { "out of" };
        let patch = Call::of("PATCH", &format!("/Groups/{}", self.group()?)).json(Scim::patch(change, &user_id));
        match Scim::member_of(&group, &user_id) {
            Some(holds) if holds == wanted => {
                return Ok(Outcome::already(&format!("{} was already {way} {}, and the directory was asked to change nothing.", plan.about().email(), plan.target())));
            }
            Some(_) => {
                self.ask(ticket, patch, action, now).await?;
            }
            None => {
                if self.ask_unread(ticket, patch, change, action, now).await? {
                    return Ok(Outcome::already(&format!("{} was already {way} {}: the directory said so when asked to change it.", plan.about().email(), plan.target())));
                }
            }
        }
        Ok(Outcome::done(&format!("{} is now {way} {}.", plan.about().email(), plan.target())))
    }

    /// Sends a change that reading could not rule out, and says whether the directory answered
    /// that it was already so. Any other refusal stays a refusal.
    async fn ask_unread(&self, ticket: &Ticket, call: Call, change: Change, action: &str, now: i64) -> Result<bool, Trouble> {
        let reply = match self.wire.send(ticket, call, now).await {
            Ok(reply) => reply,
            Err(trouble) => {
                self.record(now, action, Decision::Refused, trouble.say());
                return Err(trouble);
            }
        };
        let already = match change {
            Change::Give => reply.already(),
            Change::TakeBack => reply.status == 400 && reply.json()["scimType"] == "noTarget",
        };
        if reply.ok() || already {
            self.record(now, action, Decision::Allowed, &self.with_version(&reply.said()));
            return Ok(already);
        }
        let said = reply.said();
        self.record(now, action, Decision::Refused, &said);
        Err(Trouble::Refused(said))
    }
}

impl Connector for Scim {
    fn integration(&self) -> &'static str {
        ROW
    }

    fn destination(&self) -> &str {
        self.wire.destination()
    }

    fn discover<'a>(&'a self, ticket: &'a Ticket, now: i64) -> Answer<'a, Discovery> {
        Box::pin(async move {
            admits(ticket, self.wire.destination(), now)?;
            self.complete()?;
            let group = self.read_group(ticket, "discover", now).await?;
            let name = group["displayName"].as_str().unwrap_or("a group with no display name").to_owned();
            // A group read without its members is not said to have none.
            let (description, note) = match group["members"].as_array().map(Vec::len) {
                Some(members) => (format!("{name}, with {members} members"), format!("Reaches {name}, which has {members} members")),
                None => (format!("{name}, whose members the directory does not list"), format!("Reaches {name}; the directory does not list its members when it is read")),
            };
            Ok(Discovery { reached: vec![Found { kind: "group".into(), id: self.group()?.to_owned(), description }], note })
        })
    }

    fn plan(&self, ticket: &Ticket, request: &Request, now: i64) -> Result<Plan, Trouble> {
        admits(ticket, self.wire.destination(), now)?;
        self.complete()?;
        in_a_filter(request.about.email())?;
        let target = format!("group {}", self.group()?);
        let steps = vec![
            Step::reading("sign in to the directory with the credential this connection holds"),
            Step::reading(&format!("find {} by their userName", request.about.email())),
            Step::reading(&format!("read the members of {target}, so nothing is sent when nothing has to move")),
            Step::altering(&match request.change {
                Change::Give => format!("add them to the members of {target}"),
                Change::TakeBack => format!("remove them from the members of {target}"),
            }),
        ];
        Plan::new(ROW, ticket, request.change, request.about.clone(), &target, steps)
    }

    fn validate<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Checked> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            // Both halves of what the plan needs: the group is there, and the person is there.
            // Checking only the credential would pass a plan that cannot be carried out.
            self.read_group(ticket, "validate", now).await?;
            self.find(ticket, plan.about(), "validate", now).await?;
            Ok(Checked::passed(plan, now))
        })
    }

    fn dry_run<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Rehearsal> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            let user_id = self.find(ticket, plan.about(), "dry run", now).await?;
            let group = self.read_group(ticket, "dry run", now).await?;
            let wanted = plan.change() == Change::Give;
            let moving = if wanted { "add them to" } else { "remove them from" };
            Ok(Rehearsal {
                plan: plan.clone(),
                reached: true,
                note: match Scim::member_of(&group, &user_id) {
                    Some(holds) if holds == wanted => {
                        format!("{} is already {} {}, so carrying this out would change nothing. Nothing was changed.", plan.about().email(), if wanted { "in" } else { "out of" }, plan.target())
                    }
                    Some(_) => format!("Carrying this out would {moving} the members of {}. Nothing was changed.", plan.target()),
                    None => format!("{}. Carrying this out would ask the directory to {moving} the members either way. Nothing was changed.", Scim::unlisted(plan)),
                },
            })
        })
    }

    fn observe<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> Answer<'a, Seen> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            let user_id = self.find(ticket, plan.about(), "observe", now).await?;
            let group = self.read_group(ticket, "observe", now).await?;
            let Some(member) = Scim::member_of(&group, &user_id) else {
                return Ok(Seen { holds: None, note: Scim::unlisted(plan) });
            };
            let holds = if plan.change() == Change::Give { member } else { !member };
            Ok(Seen { holds: Some(holds), note: format!("{} {} a member of {}", plan.about().email(), if member { "is" } else { "is not" }, plan.target()) })
        })
    }

    fn apply<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> Answer<'a, Outcome> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            cleared(plan, checked, now)?;
            self.move_one(ticket, plan, plan.change(), "apply", now).await
        })
    }

    fn reconcile<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> Answer<'a, Outcome> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            cleared(plan, checked, now)?;
            // The same thing apply does. It is safe to run twice because the group is read first
            // and nothing is sent when nothing has to move, not because the directory is assumed
            // to answer a second add with a conflict.
            self.move_one(ticket, plan, plan.change(), "reconcile", now).await
        })
    }

    fn revoke<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> Answer<'a, Outcome> {
        Box::pin(async move {
            self.fits(ticket, plan, now)?;
            cleared(plan, checked, now)?;
            let undoing = match plan.change() {
                Change::Give => Change::TakeBack,
                Change::TakeBack => Change::Give,
            };
            self.move_one(ticket, plan, undoing, "revoke", now).await
        })
    }

    fn export_audit(&self) -> Vec<Note> {
        self.notes.take(ROW)
    }
}

#[cfg(test)]
mod tests;
