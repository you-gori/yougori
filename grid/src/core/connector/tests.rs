//! What the seam must hold true, whatever is behind it.
//!
//! Most of this runs against a fixture: a provider that exists only in this file, so the rules of
//! the seam can be checked without a tenant, a vendor library or a credential, none of which exist
//! in this repository. The one test that uses the four real connectors points them at the same
//! loopback servers their own tests use, so what is being checked there is that going through the
//! seam makes the provider see exactly what it saw before.
use super::intent::{Ending, IntentState};
use super::registry::{self, State};
use super::{admits, desktop::{DesktopService, Keyring}, Change, Checked, Connector, Discovery, Found, Note, Notes, Outcome, Plan, Rehearsal, Request, Seen, Settings, Step, Subject, Ticket, Trouble, CHECKED_FOR};
use crate::core::approval::Verdict;
use crate::core::audit::Decision;
use crate::core::capability::{Authority, Claims};
use crate::core::credential::{self, Credential, Secret};
use crate::core::identity::{Action, PrincipalKind, Role};
use crate::core::realm::{Capability, RealmKind};
use crate::core::Core;
use crate::enterprise::Provider;
use crate::provisioning::{tests::mock, AVD_USER_ROLE};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::sync::Mutex;

fn key() -> String {
    "b".repeat(64)
}

/// A permission for one credential at one destination, minted the way a realm mints one. It
/// outlives `CHECKED_FOR`, so a test about a stale check is about the check and not the
/// permission underneath it.
fn minted(realm_id: &str, credential_id: &str, destination: &str, now: i64) -> String {
    let claims = Claims::new(realm_id, Capability::Credentials, "principal-ada", "device-ada", "work-1", credential_id, now, 3_600).bound_to(destination, "POST", "/", 1 << 20);
    Authority::new(realm_id, &key()).mint(&claims).unwrap()
}

fn permission(realm_id: &str, credential_id: &str, destination: &str, now: i64) -> Ticket {
    Ticket::read(&minted(realm_id, credential_id, destination, now), now).unwrap()
}

fn ada() -> Subject {
    Subject::new("ada@acme.example", "Ada").unwrap()
}

// ---- A provider that exists only here ----

/// How the fixture provider is going to behave.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Mood {
    Fine,
    /// Says no before anything moves.
    Refuse,
    /// Seats the person and then fails, which is the only kind of failure that leaves work behind.
    HalfWay,
}

/// A desktop service with nothing behind it but a set of names. It implements the same nine
/// operations the real ones do, so the rules of the seam can be checked without a provider.
struct Fixture {
    destination: String,
    /// What it is pointed at. Behind a lock because a connection's settings can change between a
    /// task being asked for and the sweeper looking at it, and that is the case the sweeper's
    /// fingerprint check exists for.
    target: Mutex<&'static str>,
    settings: Settings,
    holders: Mutex<BTreeSet<String>>,
    mood: Mutex<Mood>,
    notes: Mutex<Vec<Note>>,
}

impl Fixture {
    /// Deliberately not the name of any row in the registry: a fixture is not an integration, and
    /// a test asserts that it cannot be found among them.
    const NAME: &'static str = "a fixture, which is not an integration";

    fn new(destination: &str) -> Fixture {
        Fixture {
            destination: destination.to_owned(),
            target: Mutex::new("desk pool Finance"),
            settings: Settings::new().with("pool", "Finance").unwrap(),
            holders: Mutex::new(BTreeSet::new()),
            mood: Mutex::new(Mood::Fine),
            notes: Mutex::new(Vec::new()),
        }
    }

    fn set(&self, mood: Mood) {
        *self.mood.lock().unwrap() = mood;
    }

    fn target(&self) -> &'static str {
        *self.target.lock().unwrap()
    }

    /// Points this connection somewhere else, the way an administrator editing a connection would.
    fn rename(&self, target: &'static str) {
        *self.target.lock().unwrap() = target;
    }

    fn mood(&self) -> Mood {
        *self.mood.lock().unwrap()
    }

    fn seated(&self) -> Vec<String> {
        self.holders.lock().unwrap().iter().cloned().collect()
    }

    /// How many times anything at all reached this provider, without taking the notes away the way
    /// `export_audit` does. A test about a permission that should stop short of the provider needs
    /// to say that nothing was sent, and reading a holder list cannot say that: a refused change
    /// and a change never attempted leave the same empty set behind.
    fn reached(&self) -> usize {
        self.notes.lock().unwrap().len()
    }

    fn record(&self, at: i64, action: &str, decision: Decision, reason: &str) {
        self.notes.lock().unwrap().push(Note::new(Fixture::NAME, at, action, decision, reason));
    }

    /// The whole of carrying a plan out, whichever way round it goes.
    fn move_one(&self, plan: &Plan, give: bool, action: &str, now: i64) -> Result<Outcome, Trouble> {
        let email = plan.about().email().to_owned();
        match self.mood() {
            Mood::Refuse => {
                self.record(now, action, Decision::Refused, "the fixture provider said no");
                Err(Trouble::Refused("The provider refused this change and nothing was altered".into()))
            }
            Mood::HalfWay => {
                self.holders.lock().unwrap().insert(email);
                self.record(now, action, Decision::Refused, "the fixture provider seated them and then failed");
                Err(Trouble::PartlyDone("The provider seated them and then failed before it finished. Reconcile this connection.".into()))
            }
            Mood::Fine => {
                let mut holders = self.holders.lock().unwrap();
                let held = holders.contains(&email);
                if give == held {
                    drop(holders);
                    self.record(now, action, Decision::Allowed, "nothing had to move");
                    return Ok(Outcome::already(&format!("{email} was already {} {}", if give { "on" } else { "off" }, self.target())));
                }
                if give {
                    holders.insert(email.clone());
                } else {
                    holders.remove(&email);
                }
                drop(holders);
                self.record(now, action, Decision::Allowed, "the provider was changed");
                Ok(Outcome::done(&format!("{email} is now {} {}", if give { "on" } else { "off" }, self.target())))
            }
        }
    }
}

impl Connector for Fixture {
    fn integration(&self) -> &'static str {
        Fixture::NAME
    }

    fn destination(&self) -> &str {
        &self.destination
    }

    fn discover<'a>(&'a self, ticket: &'a Ticket, now: i64) -> super::Answer<'a, Discovery> {
        Box::pin(async move {
            admits(ticket, &self.destination, now)?;
            let pool = self.settings.needed("pool", "desktop pool")?.to_owned();
            self.record(now, "discover", Decision::Allowed, "read the target");
            Ok(Discovery { reached: vec![Found { kind: "desk pool".into(), id: pool, description: format!("Reaches {}", self.target()) }], note: format!("Reaches {}", self.target()) })
        })
    }

    fn plan(&self, ticket: &Ticket, request: &Request, now: i64) -> Result<Plan, Trouble> {
        admits(ticket, &self.destination, now)?;
        self.settings.needed("pool", "desktop pool")?;
        let steps = vec![
            Step::reading("sign in to the fixture provider"),
            Step::reading(&format!("find {}", request.about.email())),
            Step::altering(&format!("{} {} {}", request.change.word(), request.about.email(), self.target())),
        ];
        Plan::new(Fixture::NAME, ticket, request.change, request.about.clone(), self.target(), steps)
    }

    fn validate<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> super::Answer<'a, Checked> {
        Box::pin(async move {
            admits(ticket, &self.destination, now)?;
            if plan.connector() != Fixture::NAME {
                return Err(Trouble::NotAllowed("This plan is for another connector".into()));
            }
            if self.mood() == Mood::Refuse {
                self.record(now, "validate", Decision::Refused, "the fixture provider said no");
                return Err(Trouble::Refused("The provider would not answer, so this plan has not been checked".into()));
            }
            self.record(now, "validate", Decision::Allowed, "the provider answered");
            Ok(Checked::passed(plan, now))
        })
    }

    fn dry_run<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> super::Answer<'a, Rehearsal> {
        Box::pin(async move {
            admits(ticket, &self.destination, now)?;
            self.record(now, "dry run", Decision::Allowed, "read the target and went no further");
            Ok(Rehearsal { plan: plan.clone(), reached: true, note: "Nothing was changed.".into() })
        })
    }

    fn observe<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> super::Answer<'a, Seen> {
        Box::pin(async move {
            admits(ticket, &self.destination, now)?;
            let holds = self.holders.lock().unwrap().contains(plan.about().email());
            self.record(now, "observe", Decision::Allowed, "read who is seated");
            Ok(Seen { holds: Some(holds), note: format!("{} {} {}", plan.about().email(), if holds { "is on" } else { "is not on" }, self.target()) })
        })
    }

    fn apply<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> super::Answer<'a, Outcome> {
        Box::pin(async move {
            admits(ticket, &self.destination, now)?;
            super::cleared(plan, checked, now)?;
            self.move_one(plan, plan.change() == Change::Give, "apply", now)
        })
    }

    fn reconcile<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> super::Answer<'a, Outcome> {
        Box::pin(async move {
            admits(ticket, &self.destination, now)?;
            super::cleared(plan, checked, now)?;
            self.move_one(plan, plan.change() == Change::Give, "reconcile", now)
        })
    }

    fn revoke<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> super::Answer<'a, Outcome> {
        Box::pin(async move {
            admits(ticket, &self.destination, now)?;
            super::cleared(plan, checked, now)?;
            self.move_one(plan, plan.change() != Change::Give, "revoke", now)
        })
    }

    fn export_audit(&self) -> Vec<Note> {
        self.notes.lock().unwrap().clone()
    }
}

// ---- The rules of the seam ----

#[tokio::test]
async fn the_seam_discovers_rehearses_applies_reconciles_and_takes_back() {
    let now = 10_000;
    let service = Fixture::new("https://desks.acme.example");
    let ticket = permission("realm-1", "credential-1", "https://desks.acme.example", now);

    let found = service.discover(&ticket, now).await.unwrap();
    assert_eq!(found.reached.len(), 1);
    assert_eq!(found.reached[0].id, "Finance");

    let plan = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    assert_eq!(plan.steps().len(), 3);
    assert!(plan.alters() && plan.describe().contains("ada@acme.example"));

    // A dry run says what would happen and leaves the provider exactly as it found it.
    let rehearsal = service.dry_run(&ticket, &plan, now).await.unwrap();
    assert_eq!(rehearsal.plan, plan);
    assert_eq!(rehearsal.would_change().len(), 1);
    assert!(service.seated().is_empty(), "a dry run seats nobody");

    // Observing before and after says the same thing the provider would.
    assert_eq!(service.observe(&ticket, &plan, now).await.unwrap().holds, Some(false));
    let checked = service.validate(&ticket, &plan, now).await.unwrap();
    let applied = service.apply(&ticket, &plan, &checked, now).await.unwrap();
    assert!(applied.changed && !applied.already);
    assert_eq!(service.seated(), vec!["ada@acme.example".to_owned()]);
    assert_eq!(service.observe(&ticket, &plan, now).await.unwrap().holds, Some(true));

    // Reconciling is doing the same thing again, and doing it again has to be free.
    let again = service.reconcile(&ticket, &plan, &checked, now + 1).await.unwrap();
    let once_more = service.reconcile(&ticket, &plan, &checked, now + 2).await.unwrap();
    assert!(again.already && !again.changed, "{}", again.note);
    assert_eq!(again, once_more, "reconciling twice says the same thing twice");
    assert_eq!(service.seated(), vec!["ada@acme.example".to_owned()], "and seats nobody twice");

    // Every change can be undone, and undoing it twice is free as well.
    let taken_back = service.revoke(&ticket, &plan, &checked, now + 3).await.unwrap();
    assert!(taken_back.changed && service.seated().is_empty());
    assert!(service.revoke(&ticket, &plan, &checked, now + 4).await.unwrap().already);

    // A profile holds whichever connector it was given, so the seam has to work through a
    // reference to the trait and not only through the type that implements it.
    let behind_the_seam: &dyn Connector = &service;
    assert_eq!(behind_the_seam.destination(), "https://desks.acme.example");
    assert!(behind_the_seam.discover(&ticket, now + 5).await.is_ok());

    // The realm gets a record of all of it, and writes it itself.
    let notes = service.export_audit();
    assert!(notes.iter().any(|note| note.action == "discover") && notes.iter().any(|note| note.action == "revoke"));
    assert!(notes.iter().all(|note| note.decision == Decision::Allowed));
    let entry = notes[0].entry("realm-1", "principal-ada", "credential-1");
    assert_eq!((entry.action.as_str(), entry.resource_id.as_deref()), ("connector.discover", Some("credential-1")));
    assert!(entry.reason.contains(Fixture::NAME));
}

#[tokio::test]
async fn nothing_changes_a_provider_until_that_exact_plan_has_been_checked() {
    let now = 20_000;
    let service = Fixture::new("https://desks.acme.example");
    let ticket = permission("realm-1", "credential-1", "https://desks.acme.example", now);
    let giving = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    let taking_back = service.plan(&ticket, &Request::new(Change::TakeBack, ada()), now).unwrap();

    // A provider that will not answer leaves no proof at all, so there is nothing to pass to
    // apply and the call cannot be written. That is the gate; everything below is the rest of it.
    service.set(Mood::Refuse);
    assert!(matches!(service.validate(&ticket, &giving, now).await, Err(Trouble::Refused(_))));
    service.set(Mood::Fine);

    let for_giving = service.validate(&ticket, &giving, now).await.unwrap();
    // A proof covers one plan. The other plan is not that plan, however alike they look.
    let wrong_plan = service.apply(&ticket, &taking_back, &for_giving, now).await.unwrap_err();
    assert!(matches!(wrong_plan, Trouble::NotAllowed(_)) && wrong_plan.say().contains("not the plan that was checked"));
    // And it goes stale, so nobody carries out this morning's check this afternoon.
    let stale = service.apply(&ticket, &giving, &for_giving, now + CHECKED_FOR).await.unwrap_err();
    assert!(stale.say().contains("checked too long ago"));
    // Reconcile and revoke are behind the same gate, because both change a provider.
    assert!(service.reconcile(&ticket, &giving, &for_giving, now + CHECKED_FOR).await.is_err());
    assert!(service.revoke(&ticket, &giving, &for_giving, now + CHECKED_FOR).await.is_err());
    assert!(service.seated().is_empty(), "nothing moved while the plan was refused");

    assert!(service.apply(&ticket, &giving, &for_giving, now + CHECKED_FOR - 1).await.is_ok());
    assert_eq!(service.seated(), vec!["ada@acme.example".to_owned()]);
}

#[tokio::test]
async fn a_connector_that_fails_part_way_leaves_the_realm_exactly_as_it_was() {
    let folder = tempfile::tempdir().unwrap();
    let now = 30_000;
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::User], now).unwrap();
    let credential = Credential::new(
        core.realm().id.clone().as_str(),
        "Acme desks",
        Secret::ApiKey,
        "vault-desks",
        &credential::fingerprint_of("never written down"),
        "https://desks.acme.example",
        &person.id,
        now,
    )
    .unwrap();
    let credential = core.add_credential("owner", credential, now).unwrap();
    let before = serde_json::to_value(core.snapshot().unwrap()).unwrap();

    let service = Fixture::new(&credential.destination);
    let ticket = permission(&core.realm().id, &credential.id, &credential.destination, now);
    let plan = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    let checked = service.validate(&ticket, &plan, now).await.unwrap();
    service.set(Mood::HalfWay);
    let trouble = service.apply(&ticket, &plan, &checked, now).await.unwrap_err();

    // The provider moved and the connector failed, which is the worst case there is.
    assert!(trouble.changed_something(), "{}", trouble.say());
    assert_eq!(service.seated(), vec!["ada@acme.example".to_owned()]);
    // The realm is untouched, down to the last audit event, because a connector is never given
    // anything it could write to. Whoever called it decides what the realm records.
    assert_eq!(serde_json::to_value(core.snapshot().unwrap()).unwrap(), before);
    assert!(core.realm().keyed_by(&key()) && core.credentials().unwrap().len() == 1);

    // What it does have is its own account of the failure, in the shape the realm seals.
    let refused: Vec<Note> = service.export_audit().into_iter().filter(|note| note.decision == Decision::Refused).collect();
    assert_eq!(refused.len(), 1);
    let entry = refused[0].entry(&core.realm().id, &person.id, &credential.id);
    assert_eq!(entry.decision, Decision::Refused);
    assert!(entry.reason.contains("seated them and then failed") && !entry.reason.contains("never written down"));
}

#[test]
fn a_connectors_settings_name_things_and_cannot_hold_one() {
    // The identifiers these connectors really need are GUIDs, and they go in.
    let settings = Settings::new()
        .with("tenantId", "3f2504e0-4f89-11d3-9a0c-0305e82c3301")
        .unwrap()
        .with("applicationGroup", "ag")
        .unwrap();
    assert_eq!(settings.get("applicationGroup"), Some("ag"));
    assert_eq!(settings.names(), vec!["applicationGroup", "tenantId"]);

    // A key whose name promises a secret is refused whatever is in it.
    for name in ["clientSecret", "password", "apiKey", "accessKey", "privateKey", "certificate"] {
        let refused = Settings::new().with(name, "anything").unwrap_err();
        assert!(refused.contains("vault"), "{name}: {refused}");
    }
    // So is a value carrying one of the markers only a secret carries.
    for value in ["-----BEGIN PRIVATE KEY-----", "Bearer eyJhbGciOi", "password=hunter2"] {
        assert!(Settings::new().with("tenantId", value).is_err(), "{value}");
    }
    // A missing one is named in the words the administrator saw when they entered it.
    let missing = settings.needed("subscriptionId", "subscription ID").unwrap_err();
    assert!(matches!(missing, Trouble::Missing(_)) && missing.say().contains("subscription ID"));
}

#[test]
fn nothing_a_plan_carries_can_hold_a_secret_either() {
    let now = 70_000;
    let ticket = permission("realm-1", "credential-1", "https://desks.acme.example", now);

    // A person is named, not keyed.
    assert!(Subject::new("ada@acme.example", "Bearer eyJhbGciOi").is_err());
    assert!(Subject::new("ada@acme.example", "Ada Lovelace").is_ok());

    // A plan is shown to an administrator, carried in a fingerprint and described in the audit,
    // so neither its target nor the words of any step is somewhere a value goes.
    let steps = vec![Step::reading("sign in"), Step::altering("entitle them")];
    assert!(Plan::new("x", &ticket, Change::Give, ada(), "desk pool Finance", steps.clone()).is_ok());
    assert!(Plan::new("x", &ticket, Change::Give, ada(), "pool?token=eyJhbGciOi", steps.clone()).is_err());
    let leaking = vec![Step::reading("sign in with password=hunter2")];
    assert!(Plan::new("x", &ticket, Change::Give, ada(), "desk pool Finance", leaking).is_err());

    // And an address is where something is, not a way into it.
    let vault = || Box::new(Vault { credential_id: "credential-1", secret: json!({"password": "pw"}) });
    assert!(DesktopService::new(Provider::Horizon, "https://horizon.acme.example", "https://horizon.acme.example", Settings::new(), vault(), now).is_ok());
    assert!(DesktopService::new(Provider::Horizon, "https://horizon.acme.example?token=abc", "https://horizon.acme.example", Settings::new(), vault(), now).is_err());
    assert!(DesktopService::new(Provider::Horizon, "http://horizon.acme.example", "https://horizon.acme.example", Settings::new(), vault(), now).is_err());
}

#[tokio::test]
async fn a_permission_for_somewhere_else_is_never_spent_here() {
    let now = 40_000;
    let service = Fixture::new("https://desks.acme.example");

    let elsewhere = permission("realm-1", "credential-1", "https://desks.other.example", now);
    let refused = service.discover(&elsewhere, now).await.unwrap_err();
    assert!(matches!(refused, Trouble::NotAllowed(_)) && refused.say().contains("desks.other.example"));

    let lapsed = permission("realm-1", "credential-1", "https://desks.acme.example", now);
    assert!(service.discover(&lapsed, lapsed.expires_at()).await.unwrap_err().say().contains("expired"));

    // A permission for something other than a credential is not a connector's permission at all.
    let authority = Authority::new("realm-1", &key());
    let claims = Claims::new("realm-1", Capability::Workspaces, "principal-ada", "device-ada", "work-1", "workspace-1", now, 600).bound_to("https://desks.acme.example", "POST", "/", 1 << 20);
    let wrong = Ticket::read(&authority.mint(&claims).unwrap(), now).unwrap_err();
    assert!(wrong.contains("permission to use a credential"));

    // And what a connector is given carries no bearer string it could pass on or print.
    let token = minted("realm-1", "credential-1", "https://desks.acme.example", now);
    let ticket = Ticket::read(&token, now).unwrap();
    let shown = format!("{ticket:?}");
    let (body, signature) = token.split_once('.').unwrap();
    assert!(shown.contains("credential-1"), "{shown}");
    assert!(!shown.contains(&token) && !shown.contains(body) && !shown.contains(signature), "{shown}");
}

// ---- The four that exist ----

/// Entra ID, Microsoft Graph and Azure Resource Manager on loopback, keyed by path. The same
/// shapes the connectors' own tests use.
fn microsoft(method: &str, path: &str, body: &Value) -> (u16, Value) {
    match (method, path) {
        ("POST", "/tenant-1/oauth2/v2.0/token") => {
            if body["client_secret"] != "s3cret" {
                return (401, json!({"error": "invalid_client", "error_description": "Invalid client secret"}));
            }
            (200, json!({"access_token": "token"}))
        }
        ("GET", p) if p.starts_with("/v1.0/users/ada%40acme.example") => (200, json!({"id": "user-ada"})),
        ("GET", p) if p.starts_with("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/applicationGroups/ag?") => {
            (200, json!({"name": "ag", "properties": {"applicationGroupType": "Desktop", "hostPoolArmPath": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/hostPools/finance"}}))
        }
        ("PUT", p) if p.contains("/providers/Microsoft.Authorization/roleAssignments/") => (201, json!({"id": p.split('?').next().unwrap()})),
        ("GET", p) if p.contains("/providers/Microsoft.Authorization/roleAssignments?") => (
            200,
            json!({"value": [{
                "id": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/applicationGroups/ag/providers/Microsoft.Authorization/roleAssignments/ra-1",
                "properties": {"roleDefinitionId": format!("/subscriptions/sub-1/providers/Microsoft.Authorization/roleDefinitions/{AVD_USER_ROLE}"), "principalId": "user-ada", "scope": "/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/applicationGroups/ag"}
            }]}),
        ),
        ("DELETE", p) if p.contains("/roleAssignments/ra-1?") => (200, json!({})),
        ("GET", "/v1.0/groups/group-1?$select=id,displayName") => (200, json!({"id": "group-1", "displayName": "Cloud PC users"})),
        ("POST", "/v1.0/groups/group-1/members/$ref") => (204, Value::Null),
        ("DELETE", "/v1.0/groups/group-1/members/user-ada/$ref") => (204, Value::Null),
        _ => (404, json!({"error": {"message": format!("no route {method} {path}")}})),
    }
}

/// The vault this computer keeps. It answers for the one credential the permission names and for
/// nothing else, which is what makes the name in the permission the thing that chooses the value.
struct Vault {
    credential_id: &'static str,
    secret: Value,
}

impl Keyring for Vault {
    fn open(&self, credential_id: &str) -> Result<Value, String> {
        if credential_id == self.credential_id {
            Ok(self.secret.clone())
        } else {
            Err(format!("No credential called {credential_id} is in this computer's vault"))
        }
    }
}

/// Everything in order, the way a profile would drive one of these.
async fn whole_seam(service: &DesktopService, ticket: &Ticket, now: i64) -> (Discovery, Rehearsal, Seen, Outcome, Outcome, Outcome) {
    let found = service.discover(ticket, now).await.unwrap();
    let plan = service.plan(ticket, &Request::new(Change::Give, ada()), now).unwrap();
    assert_eq!(plan.connector(), service.integration());
    let rehearsal = service.dry_run(ticket, &plan, now).await.unwrap();
    let checked = service.validate(ticket, &plan, now).await.unwrap();
    let seen = service.observe(ticket, &plan, now).await.unwrap();
    let applied = service.apply(ticket, &plan, &checked, now).await.unwrap();
    let reconciled = service.reconcile(ticket, &plan, &checked, now).await.unwrap();
    let revoked = service.revoke(ticket, &plan, &checked, now).await.unwrap();
    (found, rehearsal, seen, applied, reconciled, revoked)
}

#[tokio::test]
async fn the_four_desktop_connectors_make_the_same_requests_through_the_seam() {
    let now = 50_000;

    // Azure Virtual Desktop. Azure answers a role assignment somebody already has with a
    // conflict rather than making a second one, and that answer is the whole reason running a
    // plan twice is safe, so the mock gives it: the first assignment is made, every later one
    // for the same person is refused as already there.
    let made = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (base, seen) = mock(move |method: &str, path: &str, body: &Value| {
        if method == "PUT" && path.contains("/providers/Microsoft.Authorization/roleAssignments/") && made.fetch_add(1, std::sync::atomic::Ordering::SeqCst) > 0 {
            return (409, json!({"error": {"code": "RoleAssignmentExists", "message": "The role assignment already exists."}}));
        }
        microsoft(method, path, body)
    })
    .await;
    let settings = Settings::new()
        .with("tenantId", "tenant-1")
        .unwrap()
        .with("clientId", "app-1")
        .unwrap()
        .with("subscriptionId", "sub-1")
        .unwrap()
        .with("resourceGroup", "rg")
        .unwrap()
        .with("applicationGroup", "ag")
        .unwrap()
        .with("_login", &base)
        .unwrap()
        .with("_graph", &base)
        .unwrap()
        .with("_arm", &base)
        .unwrap();
    let vault = Vault { credential_id: "credential-avd", secret: json!({"clientSecret": "s3cret"}) };
    let azure = DesktopService::new(Provider::AzureVirtualDesktop, "https://management.azure.com", "https://client.wvd.microsoft.com", settings, Box::new(vault), now).unwrap();
    let ticket = permission("realm-1", "credential-avd", "https://management.azure.com", now);
    let (found, rehearsal, observed, applied, reconciled, revoked) = whole_seam(&azure, &ticket, now).await;
    assert!(found.note.contains("host pool finance") && found.reached[0].kind == "application group");
    assert!(rehearsal.reached && rehearsal.would_change().len() == 1 && rehearsal.note.contains("Nothing was changed"));
    assert_eq!(observed.holds, None, "this provider API reads the group, not one person's entitlement");
    assert!(applied.changed && applied.note.contains("may now use"));
    // Running the plan a second time leaves the tenant where the first run left it, and the
    // connector says so rather than reporting a change it did not make.
    assert!(reconciled.already && !reconciled.changed, "{}", reconciled.note);
    assert!(revoked.note.contains("no longer"));
    let calls = seen.lock().unwrap().clone();
    let puts: Vec<_> = calls.iter().filter(|(method, _, _, _)| method == "PUT").collect();
    assert_eq!(puts.len(), 2, "one for apply and one for reconcile, each the same request");
    assert!(puts[0].1.starts_with("/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.DesktopVirtualization/applicationGroups/ag/providers/Microsoft.Authorization/roleAssignments/"));
    assert!(puts[0].3.contains(AVD_USER_ROLE) && puts[0].3.contains("user-ada"));
    assert_eq!(puts[0].3, puts[1].3, "reconcile asks for the same assignment apply asked for");
    let deletes: Vec<_> = calls.iter().filter(|(method, _, _, _)| method == "DELETE").collect();
    assert_eq!(deletes.len(), 1, "revoke takes back only the assignment this grid made");
    assert!(calls.iter().all(|(_, _, _, body)| !body.contains("s3cret") || body.contains("client_secret=s3cret")), "the secret goes only to the token endpoint");
    let kept = azure.export_audit();
    assert!(kept.iter().all(|note| !note.reason.contains("s3cret")));
    assert_eq!(kept.len(), 7, "one note for each operation that reached the provider");
    assert!(azure.export_audit().is_empty(), "and taking them left the connector holding none");

    // Windows 365.
    let (base, seen) = mock(microsoft).await;
    let settings = Settings::new().with("tenantId", "tenant-1").unwrap().with("clientId", "app-1").unwrap().with("groupId", "group-1").unwrap().with("_login", &base).unwrap().with("_graph", &base).unwrap();
    let vault = Vault { credential_id: "credential-w365", secret: json!({"clientSecret": "s3cret"}) };
    let cloud_pc = DesktopService::new(Provider::Windows365, "https://graph.microsoft.com", "https://windows365.microsoft.com", settings, Box::new(vault), now).unwrap();
    let ticket = permission("realm-1", "credential-w365", "https://graph.microsoft.com", now);
    let (found, _, _, applied, _, revoked) = whole_seam(&cloud_pc, &ticket, now).await;
    assert!(found.note.contains("Cloud PC users"));
    assert!(applied.note.contains("in the group") && revoked.note.contains("out of the group"));
    let calls = seen.lock().unwrap().clone();
    assert!(calls.iter().any(|(method, path, _, body)| method == "POST" && path.ends_with("/members/$ref") && body.contains("directoryObjects/user-ada")));
    assert!(calls.iter().any(|(method, path, _, _)| method == "DELETE" && path == "/v1.0/groups/group-1/members/user-ada/$ref"));

    // Citrix DaaS.
    let (base, seen) = mock(|method, path, body| match (method, path) {
        ("POST", "/cctrustoauth2/root/tokens/clients") => {
            if body["client_secret"] == "cs" {
                (200, json!({"access_token": "ctx-token"}))
            } else {
                (401, json!({"error": "invalid_client"}))
            }
        }
        ("GET", "/cvad/manage/me") => (200, json!({"Customers": [{"Id": "acme", "Sites": [{"Id": "site-1"}]}]})),
        ("GET", "/cvad/manage/DeliveryGroups/Desks") => (200, json!({"Name": "Desks", "TotalDesktops": 12})),
        ("PATCH", "/cvad/manage/DeliveryGroups/Desks") => (200, json!({"Name": "Desks"})),
        _ => (404, json!({"error": {"message": "no"}})),
    })
    .await;
    let settings = Settings::new().with("customerId", "acme").unwrap().with("clientId", "api-client").unwrap().with("deliveryGroup", "Desks").unwrap().with("_citrix", &base).unwrap();
    let vault = Vault { credential_id: "credential-citrix", secret: json!({"clientSecret": "cs"}) };
    let citrix = DesktopService::new(Provider::Citrix, "https://api.cloud.com", "https://acme.cloud.com", settings, Box::new(vault), now).unwrap();
    let ticket = permission("realm-1", "credential-citrix", "https://api.cloud.com", now);
    let (found, _, _, applied, _, revoked) = whole_seam(&citrix, &ticket, now).await;
    assert!(found.note.contains("12 desktops"));
    assert!(applied.note.contains("in the delivery group") && revoked.note.contains("out of the delivery group"));
    let calls = seen.lock().unwrap().clone();
    let patches: Vec<_> = calls.iter().filter(|(method, _, _, _)| method == "PATCH").collect();
    assert_eq!(patches.len(), 3, "apply, reconcile and revoke");
    assert!(patches[0].3.contains("\"Users\":[\"ada@acme.example\"]") && patches[2].3.contains("\"RemoveUsers\""));
    assert!(patches.iter().all(|(_, _, authorization, _)| authorization == "CwsAuth Bearer=ctx-token"));

    // Omnissa Horizon.
    let (base, seen) = mock(|method, path, body| match (method, path) {
        ("POST", "/rest/login") => {
            if body["password"] == "pw" && body["domain"] == "ACME" {
                (200, json!({"access_token": "hz-token", "refresh_token": "r"}))
            } else {
                (401, json!({"error_message": "Invalid credentials"}))
            }
        }
        ("GET", "/rest/inventory/v1/desktop-pools/pool-1") => (200, json!({"name": "Desks", "type": "AUTOMATED"})),
        ("GET", p) if p.starts_with("/rest/external/v1/ad-users-or-groups?filter=") => (200, json!([{"id": "ad-ada", "group": false, "user_principal_name": "ada@acme.example"}])),
        ("POST", "/rest/entitlements/v1/desktop-pools") | ("DELETE", "/rest/entitlements/v1/desktop-pools") => (200, json!([{"id": "pool-1", "status_code": 200}])),
        _ => (404, json!({"error_message": "no"})),
    })
    .await;
    let settings = Settings::new().with("username", "admin").unwrap().with("domain", "ACME").unwrap().with("pool", "pool-1").unwrap();
    let vault = Vault { credential_id: "credential-horizon", secret: json!({"password": "pw"}) };
    let horizon = DesktopService::new(Provider::Horizon, "https://horizon.acme.example", &base, settings, Box::new(vault), now).unwrap();
    let ticket = permission("realm-1", "credential-horizon", "https://horizon.acme.example", now);
    let (found, _, _, applied, _, revoked) = whole_seam(&horizon, &ticket, now).await;
    assert!(found.note.contains("AUTOMATED"));
    assert!(applied.note.contains("entitled") && revoked.note.contains("no longer entitled"));
    let calls = seen.lock().unwrap().clone();
    assert!(calls.iter().any(|(method, path, authorization, body)| method == "POST" && path == "/rest/entitlements/v1/desktop-pools" && body.contains("ad-ada") && authorization == "Bearer hz-token"));
    assert!(calls.iter().any(|(method, path, _, _)| method == "DELETE" && path == "/rest/entitlements/v1/desktop-pools"));
    assert!(calls.iter().all(|(_, _, _, body)| !body.contains("\"pw\"") || body.contains("\"domain\":\"ACME\"")), "the password goes only to the sign-in");
    assert!(horizon.export_audit().iter().all(|note| !note.reason.contains("pw")));
}

/// PROVES that a connector's notes cannot grow without end and that taking them empties it.
///
/// Both halves were wrong before. The notes were a `Vec` nothing ever drained, so a connector held
/// one note per operation for as long as the process ran; and `export_audit` handed back a copy,
/// so a sweeper working through a hundred tasks sealed the first task's notes into the realm's
/// history a hundred times. The second is the worse of the two, because a history that says
/// something happened a hundred times when it happened once is a history an operator will believe.
///
/// DOES NOT PROVE that five hundred and twelve is the right cap. It is chosen in the type and the
/// reason is written there; what is proved is that the cap holds, that what is dropped is the
/// oldest, and that a drop is never silent.
#[test]
fn a_connector_holds_only_so_many_notes_and_handing_them_over_empties_it() {
    let notes = Notes::new();
    for step in 0..5 {
        notes.keep(Note::new("Windows 365", 1_000 + step, "discover", Decision::Allowed, &format!("note {step}")));
    }
    assert_eq!(notes.waiting(), 5);
    let taken = notes.take("Windows 365");
    assert_eq!(taken.len(), 5);
    assert_eq!(taken[0].reason, "note 0");
    assert_eq!(notes.waiting(), 0, "taking them leaves the connector holding none");
    assert!(notes.take("Windows 365").is_empty(), "so asking twice does not seal the same note twice");

    // Past the cap the oldest go, the newest are kept, and the first note handed over says how
    // many were lost and what an operator should do differently.
    for step in 0..(Notes::MOST + 20) {
        notes.keep(Note::new("Windows 365", 2_000 + step as i64, "apply", Decision::Allowed, &format!("note {step}")));
    }
    assert_eq!(notes.waiting(), Notes::MOST, "it never holds more than it says it holds");
    let taken = notes.take("Windows 365");
    assert_eq!(taken.len(), Notes::MOST + 1, "the cap, and one note saying what went");
    assert_eq!(taken[0].decision, Decision::Refused);
    assert!(taken[0].reason.contains("the 20 oldest were dropped") && taken[0].reason.contains("settle_connector_task"), "{}", taken[0].reason);
    assert_eq!(taken[0].at, taken[1].at, "the note about what went is stamped where the oldest survivor is, not from a clock");
    assert_eq!(taken[1].reason, "note 20", "the newest are what is kept");
    assert_eq!(taken[Notes::MOST].reason, format!("note {}", Notes::MOST + 19));

    // And the count of what was dropped goes with the notes rather than staying behind.
    notes.keep(Note::new("Windows 365", 3_000, "revoke", Decision::Allowed, "after"));
    let again = notes.take("Windows 365");
    assert_eq!(again.len(), 1, "{again:?}");
    assert_eq!(again[0].reason, "after");
}

/// PROVES that the four connectors that ship are now held to the same restraint as every
/// connector written after them: a burst and then a rate, a breaker that stops sending to a
/// provider that keeps failing, and a refusal that reaches nobody and says so.
///
/// These four had none of it. They were the only connectors in this repository that had ever been
/// pointed at anything, and they were the ones with nothing in front of them, which is the wrong
/// way round. Nothing about the requests they make has changed: the same fixture answers, and the
/// calls it records are the calls it recorded before.
///
/// DOES NOT PROVE that thirty and five are the right numbers for Microsoft Graph, Citrix or
/// Horizon. They are the same low guess `Budget::standard` is, said to be a guess where it is
/// defined, and nobody here has read a real throttle.
#[tokio::test]
async fn the_four_connectors_that_ship_hold_themselves_to_a_rate_and_stop_asking_a_provider_that_is_down() {
    let now = 61_000;
    let (base, seen) = mock(microsoft).await;
    let settings = Settings::new().with("tenantId", "tenant-1").unwrap().with("clientId", "app-1").unwrap().with("groupId", "group-1").unwrap().with("_login", &base).unwrap().with("_graph", &base).unwrap();
    let vault = Vault { credential_id: "credential-w365", secret: json!({"clientSecret": "s3cret"}) };
    let service = DesktopService::new(Provider::Windows365, "https://graph.microsoft.com", "https://windows365.microsoft.com", settings, Box::new(vault), now).unwrap();
    let ticket = permission("realm-1", "credential-w365", "https://graph.microsoft.com", now);

    // The burst, and then a refusal that never leaves this computer. Thirty operations, because
    // the budget counts operations here rather than the two or three HTTP calls each one makes.
    for _ in 0..30 {
        assert!(service.discover(&ticket, now).await.is_ok());
    }
    let sent = seen.lock().unwrap().len();
    let refused = service.discover(&ticket, now).await.unwrap_err();
    assert!(matches!(refused, Trouble::Refused(_)) && refused.say().contains("Nothing was sent"), "{}", refused.say());
    assert_eq!(seen.lock().unwrap().len(), sent, "the thirty-first reached nobody");
    // And it is in the connector's own notes, so the realm learns about it with everything else.
    let kept = service.export_audit();
    assert!(kept.iter().any(|note| note.decision == Decision::Refused && note.reason.contains("as many requests as it allows itself")), "{kept:?}");

    // A second later there are five more and no more than five.
    for _ in 0..5 {
        assert!(service.discover(&ticket, now + 1).await.is_ok());
    }
    assert!(service.discover(&ticket, now + 1).await.is_err());

    // A provider that has stopped answering: five refusals in a row and this connection stops
    // sending, rather than keeping a queue of requests warm against a service that is not there.
    let (down, calls) = mock(|_, _, _| (500, json!({"error": {"message": "the service is unavailable"}}))).await;
    let settings = Settings::new().with("tenantId", "tenant-1").unwrap().with("clientId", "app-1").unwrap().with("groupId", "group-1").unwrap().with("_login", &down).unwrap().with("_graph", &down).unwrap();
    let vault = Vault { credential_id: "credential-w365", secret: json!({"clientSecret": "s3cret"}) };
    let broken = DesktopService::new(Provider::Windows365, "https://graph.microsoft.com", "https://windows365.microsoft.com", settings, Box::new(vault), now).unwrap();
    for _ in 0..5 {
        assert!(broken.discover(&ticket, now + 60).await.is_err());
    }
    let reached = calls.lock().unwrap().len();
    let open = broken.discover(&ticket, now + 60).await.unwrap_err();
    assert!(open.say().contains("stopped sending after 5 refusals"), "{}", open.say());
    assert_eq!(calls.lock().unwrap().len(), reached, "the sixth never left this computer either");
}

#[tokio::test]
async fn a_desktop_connector_refuses_a_permission_for_another_credential() {
    let now = 60_000;
    let (base, _) = mock(microsoft).await;
    let settings = Settings::new().with("tenantId", "tenant-1").unwrap().with("clientId", "app-1").unwrap().with("groupId", "group-1").unwrap().with("_login", &base).unwrap().with("_graph", &base).unwrap();
    let vault = Vault { credential_id: "credential-w365", secret: json!({"clientSecret": "s3cret"}) };
    let service = DesktopService::new(Provider::Windows365, "https://graph.microsoft.com", "https://windows365.microsoft.com", settings, Box::new(vault), now).unwrap();

    // The name in the permission chooses the value, so a permission for another credential finds
    // nothing in the vault and nothing is sent.
    let stranger = permission("realm-1", "credential-somebody-else", "https://graph.microsoft.com", now);
    let refused = service.discover(&stranger, now).await.unwrap_err();
    assert!(matches!(refused, Trouble::NotAllowed(_)) && refused.say().contains("credential-somebody-else"));

    // A connection missing one of the identifiers the provider needs says which one, before
    // anything is sent anywhere.
    let bare = DesktopService::new(
        Provider::Windows365,
        "https://graph.microsoft.com",
        "https://windows365.microsoft.com",
        Settings::new().with("tenantId", "tenant-1").unwrap(),
        Box::new(Vault { credential_id: "credential-w365", secret: json!({"clientSecret": "s3cret"}) }),
        now,
    )
    .unwrap();
    let ticket = permission("realm-1", "credential-w365", "https://graph.microsoft.com", now);
    let missing = bare.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap_err();
    assert!(matches!(missing, Trouble::Missing(_)) && missing.say().contains("client ID"));
}

// ---- Read-only connectors, and why they cannot be made to change anything ----

/// A connector that only reads. Every plan it makes has reading steps and nothing else, which is
/// what the refusal rests on.
struct ReadsOnly {
    destination: String,
    notes: Mutex<Vec<Note>>,
}

impl ReadsOnly {
    const NAME: &'static str = "a read-only fixture, which is not an integration";
}

impl Connector for ReadsOnly {
    fn integration(&self) -> &'static str {
        ReadsOnly::NAME
    }

    fn destination(&self) -> &str {
        &self.destination
    }

    fn alters_anything(&self) -> bool {
        false
    }

    fn discover<'a>(&'a self, ticket: &'a Ticket, now: i64) -> super::Answer<'a, Discovery> {
        Box::pin(async move {
            admits(ticket, &self.destination, now)?;
            self.notes.lock().unwrap().push(Note::new(ReadsOnly::NAME, now, "discover", Decision::Allowed, "read the target"));
            Ok(Discovery { reached: vec![Found { kind: "thing".into(), id: "one".into(), description: "one thing".into() }], note: "Reaches one thing".into() })
        })
    }

    fn plan(&self, ticket: &Ticket, request: &Request, now: i64) -> Result<Plan, Trouble> {
        admits(ticket, &self.destination, now)?;
        Plan::new(ReadsOnly::NAME, ticket, request.change, request.about.clone(), "one thing", vec![Step::reading("read it"), Step::reading("change nothing")])
    }

    fn validate<'a>(&'a self, ticket: &'a Ticket, plan: &'a Plan, now: i64) -> super::Answer<'a, Checked> {
        Box::pin(async move {
            admits(ticket, &self.destination, now)?;
            Ok(Checked::passed(plan, now))
        })
    }

    fn dry_run<'a>(&'a self, _ticket: &'a Ticket, plan: &'a Plan, _now: i64) -> super::Answer<'a, Rehearsal> {
        Box::pin(async move { Ok(Rehearsal { plan: plan.clone(), reached: true, note: "Nothing was changed.".into() }) })
    }

    fn observe<'a>(&'a self, _ticket: &'a Ticket, _plan: &'a Plan, _now: i64) -> super::Answer<'a, Seen> {
        Box::pin(async move { Ok(Seen { holds: None, note: "this connector is not about a person".into() }) })
    }

    // These three are written as if the author had forgotten the rule, to show that the rule does
    // not depend on the author remembering it.
    fn apply<'a>(&'a self, _ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> super::Answer<'a, Outcome> {
        Box::pin(async move {
            super::cleared(plan, checked, now)?;
            Ok(Outcome::done("this should never be reached"))
        })
    }

    fn reconcile<'a>(&'a self, _ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> super::Answer<'a, Outcome> {
        Box::pin(async move {
            super::cleared(plan, checked, now)?;
            Ok(Outcome::done("this should never be reached"))
        })
    }

    fn revoke<'a>(&'a self, _ticket: &'a Ticket, plan: &'a Plan, checked: &'a Checked, now: i64) -> super::Answer<'a, Outcome> {
        Box::pin(async move {
            super::cleared(plan, checked, now)?;
            Ok(Outcome::done("this should never be reached"))
        })
    }

    fn export_audit(&self) -> Vec<Note> {
        self.notes.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn a_read_only_connector_cannot_be_made_to_change_anything() {
    let now = 80_000;
    let service = ReadsOnly { destination: "https://cloud.acme.example".into(), notes: Mutex::new(Vec::new()) };
    let ticket = permission("realm-1", "credential-1", "https://cloud.acme.example", now);

    // The five that read all work, and that is the point of shipping one of these: an
    // administrator can find out what a credential reaches and what is true now.
    assert_eq!(service.discover(&ticket, now).await.unwrap().reached.len(), 1);
    let plan = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    assert!(!plan.alters() && plan.steps().len() == 2);
    assert!(service.dry_run(&ticket, &plan, now).await.is_ok());
    let checked = service.validate(&ticket, &plan, now).await.unwrap();
    assert!(service.observe(&ticket, &plan, now).await.is_ok());

    // The three that change a provider refuse, and they refuse inside `cleared`, which every
    // connector calls before it does anything. The connector above tries to carry the plan out
    // and never gets there, so this is a fact about the calls and not about how it was written.
    for refused in [
        service.apply(&ticket, &plan, &checked, now).await,
        service.reconcile(&ticket, &plan, &checked, now).await,
        service.revoke(&ticket, &plan, &checked, now).await,
    ] {
        let trouble = refused.unwrap_err();
        assert!(matches!(trouble, Trouble::NotAllowed(_)));
        assert!(trouble.say().starts_with(ReadsOnly::NAME) && trouble.say().contains("only reads"), "{}", trouble.say());
        // One sentence, in one place, so every read-only connector says the same thing.
        assert_eq!(trouble, super::reads_only(ReadsOnly::NAME));
    }
    assert!(!service.alters_anything());

    // A connector that does change things is unaffected: the default answer is yes, and its plans
    // have an altering step, so nothing about the four that ship changes.
    let changes = Fixture::new("https://desks.acme.example");
    assert!(changes.alters_anything(), "the default is yes, so the connectors that already exist are untouched by this answering at all");
    let desks = permission("realm-1", "credential-1", "https://desks.acme.example", now);
    let plan = changes.plan(&desks, &Request::new(Change::Give, ada()), now).unwrap();
    assert!(plan.alters());
    let checked = changes.validate(&desks, &plan, now).await.unwrap();
    assert!(changes.apply(&desks, &plan, &checked, now).await.is_ok());
}

// ---- What the realm wrote down before it asked ----

/// A realm with one person, one computer, one credential and an agreement to use it, which is the
/// least a connector task needs.
struct Grid {
    core: Core,
    person: String,
    device: String,
    credential: String,
    work: String,
    _folder: tempfile::TempDir,
}

async fn grid(now: i64) -> Grid {
    use crate::core::work::{Kind, Resources, Workload};
    let folder = tempfile::tempdir().unwrap();
    let mut core = Core::create(&folder.path().join("realm.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    // The person places the work and somebody else agrees to the credential being used, because a
    // connector task is still a credential being spent and nobody approves their own.
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::User, Role::Operator], now).unwrap();
    let approver = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialApprover], now).unwrap();
    let (device, _) = core.enrol_device(&person.id, "Ada's laptop", "windows", now).unwrap();
    let credential = Credential::new(
        core.realm().id.clone().as_str(),
        "Acme desks",
        Secret::ApiKey,
        "vault-desks",
        &credential::fingerprint_of("never written down"),
        "https://desks.acme.example",
        &person.id,
        now,
    )
    .unwrap();
    let credential = core.add_credential("owner", credential, now).unwrap();
    core.allow_credential("owner", &credential.id, &person.id, &["POST"], &["/"], None, now).unwrap();
    let request = core.ask_for_credential(&person.id, &credential.id, "POST", "/", 3_600, now).unwrap();
    core.decide(&request.id, Action::ApproveCredential, &approver.id, Verdict::Hours(24), now).unwrap();
    let work = Workload::new(&core.realm().id, Capability::Credentials, Kind::ConnectorTask, &person.id, &device.id, Resources::default(), 1, now);
    let work = core.submit(work, now).unwrap();
    Grid { core, person: person.id, device: device.id, credential: credential.id, work: work.id, _folder: folder }
}

#[tokio::test]
async fn an_intent_survives_a_connector_that_moved_a_provider_and_then_failed() {
    let now = 90_000;
    let mut grid = grid(now).await;
    let service = Fixture::new("https://desks.acme.example");
    let ticket = permission(&grid.core.realm().id, &grid.credential, "https://desks.acme.example", now);
    let plan = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();

    let before = serde_json::to_value(grid.core.snapshot().unwrap()).unwrap();
    let (intent, token) = grid.core.open_connector_task("owner", &grid.person, &grid.device, &grid.work, &grid.credential, Fixture::NAME, &plan, "POST", "/", 600, now).unwrap();
    assert_eq!(intent.state, IntentState::Opened);
    assert_eq!(intent.fingerprint, plan.fingerprint());
    assert_eq!(intent.subject_email, "ada@acme.example");
    assert!(Ticket::read(&token, now).is_ok(), "the task opens with a permission the connector can read");

    // The provider moves and the connector fails, which is the worst case there is.
    let ticket = Ticket::read(&token, now).unwrap();
    let checked = service.validate(&ticket, &plan, now).await.unwrap();
    service.set(Mood::HalfWay);
    let trouble = service.apply(&ticket, &plan, &checked, now).await.unwrap_err();
    assert!(trouble.changed_something());
    assert_eq!(service.seated(), vec!["ada@acme.example".to_owned()], "the provider moved");

    // Everything the connector saw, and the ending, land together. The head moves by the number of
    // notes plus the one event that says how the task ended, because the ending is an event too.
    let (head, _) = grid.core.snapshot().unwrap().audit.events.last().map(|event| (event.sequence, ())).unwrap();
    let notes = service.export_audit();
    let settled = grid.core.settle_connector_task("owner", &intent.id, Ending::LeftBehind(trouble.say().to_owned()), &notes, now).unwrap();
    assert_eq!(settled.state, IntentState::Orphaned);
    assert_eq!(settled.attempts, 1);
    let after = grid.core.snapshot().unwrap();
    assert_eq!(after.audit.events.last().unwrap().sequence, head + notes.len() as u64 + 1, "every note and the ending are one account of one thing");
    assert!(after.audit.verify(&key()).is_ok(), "and the chain still seals, each event over the one before it");
    // And the realm's record of where its history ends moved with them. Settling a task writes
    // events inside a change it began itself, so it cannot call `append_events`; both go through
    // one `chain_onto` for that reason, and this is the line that fails if a second way of sealing
    // events ever appears and forgets the head.
    grid.core.verify_audit().unwrap();
    assert!(after.audit.events.iter().any(|event| event.action == "connector.task.left behind" && event.decision == Decision::Refused));

    // The realm never believed the change happened, and it never believed it did not.
    assert_ne!(serde_json::to_value(&after).unwrap(), before, "the realm wrote down what it asked for, which is the whole point");
    assert_eq!(grid.core.unsettled_connector_tasks("owner").unwrap().len(), 1, "a provider that may be out of step is a row somebody can find");
    assert!(settled.state.needs_the_sweeper() && !settled.state.settled());
}

/// PROVES that a sweep which could settle nothing does not tell an administrator that this
/// computer holds none of the connectors. Both reasons a task is left alone are counted under one
/// number, so the sentence has to name both or it sends somebody to look in the wrong place: a
/// hub that does not hold the connector is a different errand from a realm that would not take
/// the write, and the number alone cannot say which happened.
///
/// DOES NOT PROVE that the administrator learns which refusal it was. The error text is swallowed
/// inside the sweep, and carrying it out is a separate change.
#[tokio::test]
async fn a_sweep_that_could_settle_nothing_does_not_blame_a_missing_connector() {
    let now = 91_500;
    let mut grid = grid(now).await;
    let service = Fixture::new("https://desks.acme.example");
    let ticket = permission(&grid.core.realm().id, &grid.credential, "https://desks.acme.example", now);
    let plan = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    grid.core.open_connector_task("owner", &grid.person, &grid.device, &grid.work, &grid.credential, Fixture::NAME, &plan, "POST", "/", 600, now).unwrap();

    // One task this computer cannot re-plan, because it does not hold its connector. It is left
    // exactly as it was, and counted under the same number as a task nothing could be written
    // about, which is why the sentence has to offer both.
    let swept = super::sweep::sweep(&mut grid.core, "owner", &std::collections::BTreeMap::new(), now + 10).await.unwrap();
    assert_eq!(swept.skipped, 1);
    assert_eq!(service.reached(), 0, "a task whose connector is absent reaches no provider");
    let said = swept.describe();
    assert!(said.contains("1 left untouched"), "{said}");
    assert!(said.contains("does not hold their connector"), "{said}");
    assert!(said.contains("or nothing could be written about them"), "one number covers two errands, so naming only one of them sends somebody to the wrong place: {said}");
    assert_eq!(grid.core.unsettled_connector_tasks("owner").unwrap().len(), 1, "the row is still there for a computer that can settle it");
}

/// PROVES that spending a credential at a provider needs the permission to spend one, asked for
/// before anything is sent.
///
/// An auditor may list every unsettled task in the grid, which is the only permission a sweep used
/// to ask for. Everything that reaches the provider — making the plan again, checking it, carrying
/// it out — happened next, and only then did writing the row down ask whether this person could
/// manage credentials at all. A refusal that arrives after the provider has moved somebody is not
/// a refusal; it is a report. So an auditor could seat a person on a desk pool and the grid's own
/// answer was that they were not allowed to say so.
///
/// Undoing is the same door and is checked the same way, because `roll_back` moves a provider too.
///
/// DOES NOT PROVE anything about which permission the credential itself needs. That is checked
/// separately, against the principal named on the task rather than against whoever swept.
#[tokio::test]
async fn a_reader_who_may_not_spend_a_credential_is_refused_before_the_provider_is_reached() {
    let now = 92_500;
    let mut grid = grid(now).await;
    let reader = grid.core.add_principal("owner", PrincipalKind::Person, "Hedy", &[Role::Auditor], now).unwrap().id;
    let service = Fixture::new("https://desks.acme.example");
    let ticket = permission(&grid.core.realm().id, &grid.credential, "https://desks.acme.example", now);
    let plan = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    let (intent, _) = grid.core.open_connector_task("owner", &grid.person, &grid.device, &grid.work, &grid.credential, Fixture::NAME, &plan, "POST", "/", 600, now).unwrap();
    assert_eq!(service.reached(), 0, "nothing has been sent to the provider yet");

    // The connector is loaded and the task is real. The only thing missing is the permission, and
    // that alone has to be enough to stop the sweep before the provider hears anything.
    let mut connectors: std::collections::BTreeMap<String, &dyn Connector> = std::collections::BTreeMap::new();
    connectors.insert(Fixture::NAME.to_owned(), &service);
    let refused = super::sweep::sweep(&mut grid.core, &reader, &connectors, now + 10).await.unwrap_err();
    assert!(!refused.is_empty(), "the sweep says why it stopped");
    assert_eq!(service.reached(), 0, "the provider was never reached: {refused}");
    assert!(service.seated().is_empty(), "and nobody was seated by somebody who may not spend a credential");

    let refused = super::sweep::roll_back(&mut grid.core, &reader, &service, &intent, now + 10).await.unwrap_err();
    assert!(!refused.is_empty());
    assert_eq!(service.reached(), 0, "undoing is the same door and stops at the same place: {refused}");

    // The task is untouched, so whoever may settle it still finds it exactly as it was.
    let still = grid.core.unsettled_connector_tasks("owner").unwrap();
    assert_eq!(still.len(), 1);
    assert_eq!(still[0].state, IntentState::Opened);
    assert_eq!(still[0].attempts, 0, "a refused sweep does not spend one of the task's tries");
}

#[tokio::test]
async fn the_database_refuses_what_the_code_forgot() {
    let now = 91_000;
    let mut grid = grid(now).await;
    let service = Fixture::new("https://desks.acme.example");
    let ticket = permission(&grid.core.realm().id, &grid.credential, "https://desks.acme.example", now);
    let plan = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    let (intent, _) = grid.core.open_connector_task("owner", &grid.person, &grid.device, &grid.work, &grid.credential, Fixture::NAME, &plan, "POST", "/", 600, now).unwrap();

    // The same person, the same credential, the same target, the same direction, twice: an
    // administrator pressing a button twice must not make two changes at a provider that counts
    // them, and the database is what refuses it rather than a convention in the code.
    let twice = grid.core.open_connector_task("owner", &grid.person, &grid.device, &grid.work, &grid.credential, Fixture::NAME, &plan, "POST", "/", 600, now).unwrap_err();
    assert!(twice.contains("already in the middle of making that same change"), "{twice}");

    // The other direction is a different change and is allowed, which is the thing an index on the
    // credential and the email alone would have got wrong.
    let back = service.plan(&ticket, &Request::new(Change::TakeBack, ada()), now).unwrap();
    assert!(grid.core.open_connector_task("owner", &grid.person, &grid.device, &grid.work, &grid.credential, Fixture::NAME, &back, "POST", "/", 600, now).is_ok());

    // A settled task is settled. Re-settling one would let the sweeper act twice on one change.
    grid.core.settle_connector_task("owner", &intent.id, Ending::AlreadyTrue("nothing had to move".into()), &[], now).unwrap();
    let again = grid.core.settle_connector_task("owner", &intent.id, Ending::Reconciled("put right".into()), &[], now).unwrap_err();
    assert!(again.contains("cannot become"), "{again}");

    // And the state machine refuses to go backwards whatever anybody passes.
    let refused = grid.core.settle_connector_task("owner", &intent.id, Ending::Changed("moved".into()), &[], now).unwrap_err();
    assert!(refused.contains("cannot become"), "{refused}");

    // A task nobody opened cannot be settled.
    assert!(grid.core.settle_connector_task("owner", "intent-nothing", Ending::Changed("x".into()), &[], now).is_err());
}

#[tokio::test]
async fn opening_a_task_is_refused_when_the_realm_will_not_lend_the_credential() {
    let now = 92_000;
    let mut grid = grid(now).await;
    let service = Fixture::new("https://desks.acme.example");
    let ticket = permission(&grid.core.realm().id, &grid.credential, "https://desks.acme.example", now);
    let plan = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();

    // The person is suspended between the agreement and the task. Nothing can be sent, so the row
    // is opened and settled refused in the same breath rather than left waiting for a sweeper.
    grid.core.suspend_principal("owner", &grid.person, "they left", now).unwrap();
    let refused = grid.core.open_connector_task("owner", &grid.person, &grid.device, &grid.work, &grid.credential, Fixture::NAME, &plan, "POST", "/", 600, now).unwrap_err();
    assert!(refused.contains("suspended"), "{refused}");
    let tasks = grid.core.connector_tasks("owner").unwrap();
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].state, IntentState::Refused);
    assert!(tasks[0].state.settled() && !tasks[0].state.needs_the_sweeper(), "nothing was sent, so there is nothing for a sweeper to put right");

    // A plan for another connector, or for another credential, is refused before a row is written.
    let other = Fixture::new("https://desks.acme.example");
    let elsewhere = other.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    let wrong = grid.core.open_connector_task("owner", &grid.person, &grid.device, &grid.work, &grid.credential, "Windows 365", &elsewhere, "POST", "/", 600, now).unwrap_err();
    assert!(wrong.contains("This plan is for"), "{wrong}");
    assert_eq!(grid.core.connector_tasks("owner").unwrap().len(), 1, "a refusal before the row is written leaves no row");
}

#[tokio::test]
async fn the_sweeper_refuses_a_plan_it_cannot_reproduce_and_stops_after_three_tries() {
    let now = 93_000;
    let mut grid = grid(now).await;
    let service = Fixture::new("https://desks.acme.example");
    let ticket = permission(&grid.core.realm().id, &grid.credential, "https://desks.acme.example", now);
    let plan = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    let (intent, token) = grid.core.open_connector_task("owner", &grid.person, &grid.device, &grid.work, &grid.credential, Fixture::NAME, &plan, "POST", "/", 600, now).unwrap();
    let held = Ticket::read(&token, now).unwrap();
    let checked = service.validate(&held, &plan, now).await.unwrap();
    service.set(Mood::HalfWay);
    let trouble = service.apply(&held, &plan, &checked, now).await.unwrap_err();
    grid.core.settle_connector_task("owner", &intent.id, Ending::LeftBehind(trouble.say().to_owned()), &service.export_audit(), now).unwrap();

    // The provider is put right. The sweeper mints its own permission, re-plans, compares the
    // fingerprint and reconciles, and the fixture answers that nothing had to move because the
    // person is already seated.
    service.set(Mood::Fine);
    let mut connectors: std::collections::BTreeMap<String, &dyn Connector> = std::collections::BTreeMap::new();
    connectors.insert(Fixture::NAME.to_owned(), &service);
    let swept = super::sweep::sweep(&mut grid.core, "owner", &connectors, now + 10).await.unwrap();
    assert_eq!(swept, super::sweep::Swept { reconciled: 1, stuck: 0, skipped: 0 });
    assert!(swept.describe().contains("1 brought back into step"));
    let settled = grid.core.connector_task("owner", &intent.id).unwrap().unwrap();
    assert_eq!(settled.state, IntentState::Reconciled);
    assert!(settled.state.settled());
    assert!(grid.core.unsettled_connector_tasks("owner").unwrap().is_empty());
    assert!(grid.core.verify_audit().is_ok());

    // A task whose connector this computer does not hold is left exactly as it was.
    let plan = service.plan(&ticket, &Request::new(Change::TakeBack, ada()), now).unwrap();
    let (other, _) = grid.core.open_connector_task("owner", &grid.person, &grid.device, &grid.work, &grid.credential, Fixture::NAME, &plan, "POST", "/", 600, now).unwrap();
    let swept = super::sweep::sweep(&mut grid.core, "owner", &std::collections::BTreeMap::new(), now + 20).await.unwrap();
    assert_eq!(swept.skipped, 1);
    assert_eq!(grid.core.connector_task("owner", &other.id).unwrap().unwrap().state, IntentState::Opened, "untouched");

    // A connection whose settings changed since the task opened would make a different plan now,
    // and the sweeper will not carry out a plan it cannot reproduce.
    let changed = Fixture::new("https://desks.acme.example");
    changed.rename("desk pool Research");
    let mut connectors: std::collections::BTreeMap<String, &dyn Connector> = std::collections::BTreeMap::new();
    connectors.insert(Fixture::NAME.to_owned(), &changed);
    let swept = super::sweep::sweep(&mut grid.core, "owner", &connectors, now + 30).await.unwrap();
    assert_eq!(swept.stuck, 1);
    let stuck = grid.core.connector_task("owner", &other.id).unwrap().unwrap();
    assert_eq!(stuck.state, IntentState::Stuck);
    assert!(stuck.note.contains("has changed since this task was asked for"), "{}", stuck.note);
    assert!(changed.seated().is_empty(), "nothing was sent");

    // Three tries and a person has to look. The row stays stuck rather than being tried for ever.
    for step in 0..4 {
        super::sweep::sweep(&mut grid.core, "owner", &connectors, now + 40 + step).await.unwrap();
    }
    let stuck = grid.core.connector_task("owner", &other.id).unwrap().unwrap();
    assert_eq!(stuck.state, IntentState::Stuck);
    assert!(stuck.attempts <= super::limits::TRIES + 1, "{} attempts", stuck.attempts);
}

#[tokio::test]
async fn a_sweeper_whose_realm_withdrew_the_credential_says_so_rather_than_claiming_to_have_undone_it() {
    let now = 94_000;
    let mut grid = grid(now).await;
    let service = Fixture::new("https://desks.acme.example");
    let ticket = permission(&grid.core.realm().id, &grid.credential, "https://desks.acme.example", now);
    let plan = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    let (intent, token) = grid.core.open_connector_task("owner", &grid.person, &grid.device, &grid.work, &grid.credential, Fixture::NAME, &plan, "POST", "/", 600, now).unwrap();
    let held = Ticket::read(&token, now).unwrap();
    let checked = service.validate(&held, &plan, now).await.unwrap();
    service.set(Mood::HalfWay);
    let trouble = service.apply(&held, &plan, &checked, now).await.unwrap_err();
    grid.core.settle_connector_task("owner", &intent.id, Ending::LeftBehind(trouble.say().to_owned()), &[], now).unwrap();
    assert_eq!(service.seated(), vec!["ada@acme.example".to_owned()]);

    // The realm takes the credential back. The sweeper now cannot reach the provider in either
    // direction, and says exactly that instead of reporting a rollback that never happened.
    grid.core.take_credential_back("owner", &grid.credential, &grid.person, now).unwrap();
    service.set(Mood::Fine);
    let mut connectors: std::collections::BTreeMap<String, &dyn Connector> = std::collections::BTreeMap::new();
    connectors.insert(Fixture::NAME.to_owned(), &service);
    let swept = super::sweep::sweep(&mut grid.core, "owner", &connectors, now + 10).await.unwrap();
    assert_eq!((swept.reconciled, swept.stuck, swept.skipped), (0, 1, 0));
    let stuck = grid.core.connector_task("owner", &intent.id).unwrap().unwrap();
    assert_eq!(stuck.state, IntentState::Stuck);
    assert!(stuck.note.contains("can no longer use that credential"), "{}", stuck.note);
    assert_eq!(service.seated(), vec!["ada@acme.example".to_owned()], "the person is still seated, and the realm says it does not know how to change that");

    // An administrator who gets the credential back can then undo it on purpose, which is the
    // rollback that is asked for rather than swept up.
    grid.core.allow_credential("owner", &grid.credential, &grid.person, &["POST"], &["/"], None, now).unwrap();
    let approver = grid.core.add_principal("owner", PrincipalKind::Person, "Hopper", &[Role::CredentialApprover], now).unwrap();
    let request = grid.core.ask_for_credential(&grid.person, &grid.credential, "POST", "/", 3_600, now).unwrap();
    grid.core.decide(&request.id, Action::ApproveCredential, &approver.id, Verdict::Hours(24), now).unwrap();
    let stuck = grid.core.connector_task("owner", &intent.id).unwrap().unwrap();
    let state = super::sweep::roll_back(&mut grid.core, "owner", &service, &stuck, now + 20).await.unwrap();
    assert_eq!(state, IntentState::RolledBack);
    assert!(service.seated().is_empty(), "undoing a plan that seated somebody takes the seat back");
    assert!(super::sweep::roll_back(&mut grid.core, "owner", &service, &stuck, now + 30).await.is_err(), "a settled task is settled");
    assert_eq!(super::sweep::undoing(Change::Give), Change::TakeBack);
}

// ---- The registry, and the document it renders ----

#[test]
fn no_integration_claims_more_than_this_repository_can_show() {
    assert_eq!(registry::counted(State::LiveTested), 0, "there is no tenant, no vendor library and no credential here, so nothing can have met one");
    // Nineteen things have been exercised against something on this computer that answers the way
    // the published protocol or the published format describes: the four desktop services, eight
    // read-only cloud and storage adapters, the SCIM client, Entra ID as a management target, the
    // two audit sinks that are built, and three facts this computer measures about itself.
    // Changing this number means changing the sentence beside it, which is why it is asserted
    // rather than counted.
    assert_eq!(registry::counted(State::MockTested), 19, "something has moved in the table without the headline being thought about");
    super::desktop::rows_are_honest().unwrap();
    super::cloud::rows_are_honest().unwrap();
    assert!(registry::find(Fixture::NAME).is_none(), "a fixture is not an integration and must not be able to find itself in the matrix");

    let mut names: Vec<&str> = registry::INTEGRATIONS.iter().map(|row| row.name).collect();
    let total = names.len();
    names.sort_unstable();
    names.dedup();
    assert_eq!(names.len(), total, "two rows share a name, and a connector naming one would not know which it is");
    for row in registry::INTEGRATIONS {
        assert!(!row.name.is_empty() && !row.maps_to.is_empty() && !row.evidence.is_empty(), "{} has a row with nothing in it", row.name);
        if row.state == State::Roadmap {
            assert!(
                row.evidence.contains("No code") || row.evidence.contains("No connector") || row.evidence.contains("Not a connector"),
                "{} has no connector, and its evidence has to say so plainly",
                row.name
            );
        }
        // Something that renders a vendor's envelope, or holds a type with no reader behind it,
        // has to say what is missing as well as what is there. The first half on its own reads as
        // finished, which is exactly the way this table could mislead somebody without saying a
        // single untrue thing. These are the ways a row is allowed to say it.
        if row.state == State::InterfaceOnly {
            // The first three are the ones this table has always required. The three after them
            // are for a row that does have code and still has nothing behind it, which is what an
            // envelope that renders and has never been sent is, and which "no code" would be a
            // false way of saying.
            const SAYS_WHAT_IS_MISSING: &[&str] =
                &["no code", "no connector", "not a connector", "nothing has ever sent", "nothing in this build runs", "neither tool is run", "reads neither", "and nowhere else"];
            let evidence = row.evidence.to_ascii_lowercase();
            assert!(
                SAYS_WHAT_IS_MISSING.iter().any(|marker| evidence.contains(marker)),
                "{} implements something with nothing behind it, and its evidence has to say what is missing: {}",
                row.name,
                row.evidence
            );
        }
    }
}

#[test]
fn no_row_bundles_several_systems_whose_states_have_come_apart() {
    // A row naming several systems can carry one honest state only while all of them are in it.
    // The moment one moves, the row has to be split, and this phase split four of them. What is
    // left is listed here by name, with what has to stay true of each, so adding a member to one
    // of them later is a decision somebody makes rather than a row that quietly reads better than
    // the truth.
    let still_bundled: &[(&str, State)] = &[
        // Every member is roadmap: no code anywhere in this repository for any of them.
        ("Hyper-V, Proxmox, Nutanix and KVM managers", State::Roadmap),
        ("Slurm, Nomad and Ray", State::Roadmap),
        ("ServiceNow, Jira, PagerDuty and chat", State::Roadmap),
        ("NFS and SMB", State::Roadmap),
        ("WebAuthn and FIDO2", State::Roadmap),
        ("HSM and PKCS#11 key storage", State::Roadmap),
        // These four are bundled because their members cannot come apart. The compute stacks
        // share one reader, which does not exist; the three disk encryption products answer one
        // question a realm asks once; processors, memory and disk are how large a computer is;
        // and a card and its memory are read by the same thing or by nothing.
        ("NVIDIA CUDA, AMD ROCm, Intel and Apple compute", State::InterfaceOnly),
        ("BitLocker, FileVault and LUKS", State::InterfaceOnly),
        ("Processors, memory and disk", State::MockTested),
        ("GPU presence and memory", State::MockTested),
    ];
    for (name, state) in still_bundled {
        let row = registry::find(name).unwrap_or_else(|| panic!("{name} is listed here as a row that still bundles several systems, and it is not in the table"));
        assert_eq!(row.state, *state, "{name} has moved, and a row naming several systems cannot carry one state once they come apart");
    }

    // And the four this phase split are gone, so nothing can quietly put one back.
    for split in [
        "AWS, Azure and Google Cloud compute",
        "Azure Blob, Google Cloud Storage, NFS, SMB and backup vendors",
        "Syslog over TLS, SIEM and audit export to object storage",
        "LDAP and Active Directory",
        "FIDO2 and smart cards",
    ] {
        assert!(registry::find(split).is_none(), "{split} was split because its members reached different states, and it is back");
    }
}

/// Where the document is, and what in it is rendered rather than written. Everything between the
/// states heading and the heading after the last table is the registry's; the prose on either side
/// is somebody's writing and is left alone.
const DOCUMENT: &str = "../docs/grid-core/adapters.md";
const RENDERED_FROM: &str = "## What the states mean";
const RENDERED_TO: &str = "\n## The adapter interface";

fn adapters_document() -> (std::path::PathBuf, String) {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(DOCUMENT);
    let text = std::fs::read_to_string(&path).expect("docs/grid-core/adapters.md is part of this repository").replace("\r\n", "\n");
    (path, text)
}

/// Puts what the registry renders back into the document, leaving the prose around it alone.
/// Ignored because it writes to the repository: run it on purpose, with
/// `cargo test rewrite_the_adapter_matrix -- --ignored`, after changing the table.
#[test]
#[ignore]
fn rewrite_the_adapter_matrix() {
    let (path, document) = adapters_document();
    let from = document.find(RENDERED_FROM).expect("the document still has the states heading the registry renders");
    let to = document.find(RENDERED_TO).expect("the document still has the heading that follows the last table");
    std::fs::write(&path, format!("{}{}{}", &document[..from], registry::matrix(), &document[to..])).unwrap();
}

#[test]
fn the_adapter_matrix_in_the_documentation_is_the_one_in_the_code() {
    let (_, document) = adapters_document();
    let matrix = registry::matrix();
    assert!(
        document.contains(&matrix),
        "docs/grid-core/adapters.md is no longer what the registry renders. The table in core::connector::registry is the only place any of this is written down; run `cargo test rewrite_the_adapter_matrix -- --ignored` to put it back."
    );
    // A row added to the document by hand, or a state quietly improved there, would show up as a
    // state word the table never printed.
    for state in [State::LiveTested, State::MockTested, State::InterfaceOnly, State::Roadmap] {
        assert_eq!(
            document.matches(state.name()).count(),
            matrix.matches(state.name()).count(),
            "docs/grid-core/adapters.md says {} in a place the registry did not put it",
            state.name()
        );
    }
    // The thing the whole document exists to say.
    for sentence in ["no live tenant", "no vendor", "forbidden"] {
        assert!(document.contains(sentence), "docs/grid-core/adapters.md has to say plainly that there is {sentence} here");
    }
}
