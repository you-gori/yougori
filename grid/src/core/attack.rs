//! The attacks, performed. Each test does the thing and asserts it fails.
//!
//! WHAT A PASS HERE PROVES, FOR EVERY TEST IN THIS FILE. A property of this code, on this
//! computer, under a clock the test supplies. The realm is called directly, in one thread.
//!
//! WHAT A PASS HERE DOES NOT PROVE, FOR EVERY TEST IN THIS FILE. That a deployment is safe. The
//! core authenticates nobody: it takes `by`, `device_id` and `principal_id` as text and trusts
//! whatever process embeds it to have checked them first, so every test here assumes the one
//! thing the core does not do. Nothing here proves anything about a hypervisor, a container, a
//! vault, a network, a provider's own system, or a model, and where a test comes close to one of
//! those it says in its own words which part it checked and which part it did not.
//!
//! Tests that would only restate something already covered are not here. Where this file extends
//! an existing test rather than repeating it, the existing one is named.
use super::*;
use approval::Verdict;
use capability::{Attempt, Authority, Claims};
use credential::{fingerprint_of, Credential, Secret};
use identity::{Action, PrincipalKind, Role};
use realm::{Capability, Lifecycle, NetworkPolicy, RealmKind};
use work::{Commitment, Kind, Resources, Setback, Workload};

fn key() -> String {
    "a".repeat(64)
}

fn other_key() -> String {
    "b".repeat(64)
}

fn big() -> Resources {
    Resources { cpu: 16.0, memory_gb: 64.0, disk_gb: 500.0, gpu: true, vram_gb: 24.0 }
}

/// A company realm, an administrator, a person, their computer, and a computer offering
/// resources. The administrator is a real account rather than the word "owner", because several
/// tables reference `principals(id)` and a word is not an account.
struct Company {
    core: Core,
    admin: String,
    person: String,
    device: String,
    host: String,
}

fn company(folder: &std::path::Path, name: &str, now: i64) -> Company {
    let mut core = Core::create(&folder.join(format!("{name}.db")), "Acme", RealmKind::Primary, &[Capability::Models, Capability::Workspaces, Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::RealmAdmin], now).unwrap();
    let person = core.add_principal(&admin.id, PrincipalKind::Person, "Ada", &[Role::Operator], now).unwrap();
    let (device, _) = core.enrol_device(&person.id, "Ada's laptop", "windows", now).unwrap();
    let host = core.offer_host(&device.id, "Studio PC", big(), big(), Commitment::Share, now).unwrap();
    Company { core, admin: admin.id, person: person.id, device: device.id, host: host.id }
}

/// A piece of work in the queue, so a permission has something to be minted for.
fn work_for(core: &mut Core, person: &str, device: &str, now: i64) -> String {
    let realm = core.realm().id.clone();
    let version = core.store_for_tests().policy_version().unwrap();
    let needs = Resources { cpu: 1.0, memory_gb: 1.0, disk_gb: 1.0, gpu: false, vram_gb: 0.0 };
    let work = Workload::new(&realm, Capability::Models, Kind::Inference, person, device, needs, version, now);
    core.submit(work, now).unwrap().id
}

fn attempt<'a>(realm: &'a str, device: &'a str, work: &'a str) -> Attempt<'a> {
    Attempt { realm_id: realm, device_id: device, workload_id: work, resource_id: work, ..Default::default() }
}

fn holds(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty() && needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|window| window == needle)
}

/// One named change a test makes to something it has in hand, for the tables that drive the
/// field-by-field attacks.
type Change<T> = (&'static str, Box<dyn Fn(&mut T)>);

/// An image a workspace can be built from, for the tests that need a desk to attack.
fn image(core: &mut Core, by: &str, now: i64) -> workspace::Image {
    let realm = core.realm().id.clone();
    let shape = Resources { cpu: 2.0, memory_gb: 4.0, disk_gb: 10.0, gpu: false, vram_gb: 0.0 };
    let built = workspace::Image::new(
        &realm,
        "Ubuntu",
        "24.04",
        workspace::WorkspaceKind::Container,
        None,
        workspace::ImageSource::Oci { reference: "docker.io/library/ubuntu:24.04".into() },
        shape,
        by,
        now,
    )
    .unwrap();
    core.publish_image(by, built, now).unwrap()
}

/// What a computer must present to say anything about a workspace.
fn claim_for(core: &Core, workspace_id: &str) -> workspace::Claim {
    let workspace = core.workspace(workspace_id).unwrap().unwrap();
    let placement = core.store_for_tests().live_assignment(workspace_id).unwrap().unwrap();
    workspace::Claim::new(workspace_id, workspace.generation, placement.generation, &placement.host_id)
}

/// Everything on disk for one realm: the database and its journal.
fn on_disk(path: &std::path::Path) -> Vec<u8> {
    let mut bytes = std::fs::read(path).unwrap_or_default();
    bytes.extend(std::fs::read(format!("{}-wal", path.display())).unwrap_or_default());
    bytes
}

/// Takes a token apart, changes one claim, and puts it back with its old signature.
fn edited(token: &str, change: impl FnOnce(&mut serde_json::Value)) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let (body, signature) = token.split_once('.').unwrap();
    let mut claims: serde_json::Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).unwrap()).unwrap();
    change(&mut claims);
    format!("{}.{signature}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()))
}

// ---------------------------------------------------------------------------------------------
// 1. Realm crossing
// ---------------------------------------------------------------------------------------------

/// PROVES a research realm refuses every company door before any permission check, that the two
/// realms are two files neither of which opens with the other's key, and that neither file holds
/// the other's realm id.
///
/// DOES NOT PROVE process separation. Both realms' keys live in one operating system vault under
/// one operating system user, so a process that can read one entry can read the other. It also
/// does not prove a research workload is contained at run time; that is the sandbox's boundary
/// and no test in this crate can reach it.
#[test]
fn two_realms_on_one_computer_share_no_door_no_key_and_no_file() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_000;
    let Company { core: company, person, device, .. } = company(folder.path(), "company", now);
    let mut research = Core::create(&folder.path().join("research.db"), "Study", RealmKind::Research, &[Capability::Research], &other_key(), now).unwrap();
    let scholar = research.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::Researcher, Role::CredentialAdmin, Role::WorkspaceAdmin], now).unwrap();

    // Every company door is shut on the realm's own capability, before any role is consulted.
    let print = fingerprint_of("sk-live-9f2b7c41e8a24d6fb0c3e5a7d91f4b62");
    let realm = research.realm().id.clone();
    let credential = Credential::new(&realm, "Billing", Secret::ApiKey, "yougori-credential-billing", &print, "https://api.acme.test", &scholar.id, now).unwrap();
    assert!(research.add_credential(&scholar.id, credential, now).unwrap_err().contains("broker credentials"));
    assert!(research.use_credential(&scholar.id, "device-none", "work-none", "credential-none", "POST", "/v1/charge", 60, now).unwrap_err().contains("broker credentials"));
    let quota = workspace::Quota::for_disk(10.0).unwrap();
    assert!(research.order_workspace(&scholar.id, "Desk", "image-none", workspace::Access::Standard, quota, None, now).unwrap_err().contains("host workspaces"));
    assert!(Realm::new("Study", RealmKind::Research, &[Capability::Credentials], &other_key(), now).unwrap_err().contains("cannot broker credentials"));
    assert_eq!(Capability::allowed_in(RealmKind::Research), &[Capability::Research]);

    // Two files, two keys, and neither opens with the other's.
    assert_ne!(company.path(), research.path());
    assert!(Core::open(company.path(), &other_key()).unwrap_err().contains("not this grid's key"));
    assert!(Core::open(research.path(), &key()).unwrap_err().contains("not this grid's key"));

    // And nothing of one realm is in the other's file.
    let _ = (person, device);
    let company_id = company.realm().id.clone();
    let research_id = research.realm().id.clone();
    company.close().unwrap();
    research.close().unwrap();
    assert!(!holds(&on_disk(&folder.path().join("company.db")), research_id.as_bytes()), "the company's file names the research realm");
    assert!(!holds(&on_disk(&folder.path().join("research.db")), company_id.as_bytes()), "the research file names the company realm");
}

// ---------------------------------------------------------------------------------------------
// 2. Token forgery
// ---------------------------------------------------------------------------------------------

/// PROVES that changing any claim in a token breaks the signature over it, in the realm that
/// minted it and in any other, and that sixty-four wrong keys all fail without marking the claim
/// spent or changing a row.
///
/// DOES NOT PROVE that HMAC-SHA256 is unforgeable. That is taken on the strength of the `hmac`
/// and `sha2` crates and is not something a test here can establish. It also says nothing about
/// an attacker who holds the realm key, which the threat model puts out of scope on purpose.
#[test]
fn a_token_edited_or_signed_with_a_guessed_key_is_refused_and_spends_nothing() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_100;
    let Company { mut core, person, device, .. } = company(folder.path(), "forgery", now);
    let work = work_for(&mut core, &person, &device, now);
    let realm = core.realm().id.clone();
    let claims = Claims::new(&realm, Capability::Models, &person, &device, &work, &work, now, 600);
    let token = core.mint(&claims).unwrap();

    // Every field a holder could want to change is inside the signed body.
    let changes: Vec<Change<serde_json::Value>> = vec![
        ("realmId", Box::new(|body: &mut serde_json::Value| body["realmId"] = "realm-somewhere-else".into())),
        ("principalId", Box::new(|body: &mut serde_json::Value| body["principalId"] = "principal-somebody-else".into())),
        ("deviceId", Box::new(|body: &mut serde_json::Value| body["deviceId"] = "device-somebody-else".into())),
        ("workloadId", Box::new(|body: &mut serde_json::Value| body["workloadId"] = "work-somebody-else".into())),
        ("resourceId", Box::new(|body: &mut serde_json::Value| body["resourceId"] = "resource-somebody-else".into())),
        ("capability", Box::new(|body: &mut serde_json::Value| body["capability"] = "credentials".into())),
        ("expiresAt", Box::new(|body: &mut serde_json::Value| body["expiresAt"] = serde_json::json!(i64::MAX / 2))),
        ("singleUse", Box::new(|body: &mut serde_json::Value| body["singleUse"] = serde_json::json!(false))),
        ("maximumBytes", Box::new(|body: &mut serde_json::Value| body["maximumBytes"] = serde_json::json!(u64::MAX))),
        ("id", Box::new(|body: &mut serde_json::Value| body["id"] = "cap-somebody-elses".into())),
    ];
    for (field, change) in changes {
        let forged = edited(&token, change);
        let refused = core.accept(&forged, &attempt(&realm, &device, &work), now).unwrap_err();
        assert!(refused.contains("not issued by this grid"), "{field} was changed and the token was still read: {refused}");
    }

    // Sixty-four wrong keys, none of which reaches anything.
    let mut dice = super::seed::Dice::seeded(0x5EED_A77A_C000_0001);
    for _ in 0..64 {
        let guessed: String = (0..64).map(|_| char::from_digit(dice.upto(16) as u32, 16).unwrap()).collect();
        if guessed == key() {
            continue;
        }
        let elsewhere = Authority::new(&realm, &guessed);
        let forged = elsewhere.mint(&claims).unwrap();
        assert!(core.accept(&forged, &attempt(&realm, &device, &work), now).is_err(), "a token signed with {guessed} was accepted");
    }
    assert!(core.store_for_tests().check_capability(&claims, now).unwrap().is_none(), "none of that spent the permission or moved a generation");

    // The real one still works, exactly once.
    core.accept(&token, &attempt(&realm, &device, &work), now).unwrap();
}

/// PROVES that a forged token carrying ten kilobytes of a stranger's text produces one refusal
/// event naming nobody, and that no byte of that text reaches any row of the realm's database.
///
/// This is the test for the fix in `Core::accept`: the signature is checked before the claims are
/// looked up, because the identifier fields of an event are not filtered the way a free-text
/// reason is. Before the fix, the text below was written into `audit_events.principal_id` and
/// sealed into the chain.
///
/// DOES NOT PROVE that every other path filters what a caller sends. Each of those has its own
/// test, and `nothing_a_stranger_sends_becomes_a_field_of_the_history` below is the general one.
#[test]
fn an_unsigned_token_never_reaches_the_database_or_the_history() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_200;
    let Company { mut core, person, device, .. } = company(folder.path(), "forged", now);
    let work = work_for(&mut core, &person, &device, now);
    let realm = core.realm().id.clone();
    let planted = format!("{}\nFAKE LOG LINE: everything was allowed\n{}", "P".repeat(5_000), "Q".repeat(5_000));

    let mut claims = Claims::new(&realm, Capability::Models, &planted, &planted, &planted, &planted, now, 600);
    claims.id = format!("cap-{planted}");
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let forged = format!("{}.{}", URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap()), "x".repeat(43));

    let before = core.since(0).unwrap().len();
    assert!(core.accept(&forged, &attempt(&realm, &device, &work), now).is_err());
    let after = core.since(0).unwrap();
    assert_eq!(after.len(), before + 1, "a refusal writes one event and no more");
    let last = after.last().unwrap();
    assert_eq!(last.principal_id, "unknown", "a refused token names nobody, because nobody has been proved");
    assert!(last.device_id.is_none() && last.workload_id.is_none());
    for event in &after {
        let printed = serde_json::to_string(event).unwrap();
        assert!(!printed.contains("FAKE LOG LINE"), "a stranger's sentence is in the history: {printed}");
    }

    // And nothing of it is anywhere in the file either.
    let path = core.path().to_owned();
    core.close().unwrap();
    assert!(!holds(&on_disk(&path), b"FAKE LOG LINE"), "a stranger's sentence reached the realm's database");
}

/// PROVES that nine shapes which are not tokens, including an input of four megabytes, are each
/// refused with a reason rather than a crash, and that none of them is ever read as claims.
///
/// DOES NOT PROVE anything about inputs this list did not reach. `fuzz::malformed_capability_
/// tokens_are_refused_rather_than_crashed_into` widens it with a seeded generator, and that one
/// explores a sample too, not a coverage target.
#[test]
fn a_token_that_is_not_a_token_is_refused_and_never_a_crash() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    let folder = tempfile::tempdir().unwrap();
    let now = 40_300;
    let Company { mut core, person, device, .. } = company(folder.path(), "malformed", now);
    let work = work_for(&mut core, &person, &device, now);
    let realm = core.realm().id.clone();

    let shapes = vec![
        String::new(),
        ".".to_owned(),
        "a.b.c".to_owned(),
        format!("{}.{}", "a".repeat(8_193), "b".repeat(43)),
        format!("{}.{}", URL_SAFE_NO_PAD.encode("{}"), "b".repeat(257)),
        URL_SAFE_NO_PAD.encode([0xff, 0xfe, 0xfd]) + ".signature",
        URL_SAFE_NO_PAD.encode("{}") + ".signature",
        URL_SAFE_NO_PAD.encode("[1,2,3]") + ".signature",
        ".".repeat(4 * 1024 * 1024),
    ];
    for shape in &shapes {
        let refused = core.accept(shape, &attempt(&realm, &device, &work), now).unwrap_err();
        assert!(!refused.is_empty(), "a refusal says something a person can read");
        assert!(Authority::new(&realm, &key()).verified(shape).is_err(), "a shape that is not a token must not verify");
    }
    // The realm is still whole after all of it.
    core.verify_audit().unwrap();
}

// ---------------------------------------------------------------------------------------------
// 3. Token replay
// ---------------------------------------------------------------------------------------------

/// PROVES that a one-use permission is spent in the database, so a restart refuses it, a second
/// realm handle opened on the same file refuses it, and the handle that did not win the race is
/// told it was already used rather than being let through.
///
/// This extends `a_single_use_permission_is_still_spent_after_a_restart` (tests.rs) with the
/// second-handle arm, which is the one that needed `spend_capability` to report whether its
/// UPDATE changed a row. Reading that answer is what makes one use mean one use when something
/// else can open the same file.
///
/// DOES NOT PROVE serializability. Both handles are driven from one thread in an order this test
/// chose. What it does prove is that the losing handle is refused, which is the property that
/// was not there before: the statement `UPDATE ... WHERE spent_at IS NULL` is atomic in SQLite,
/// and now its row count decides.
#[test]
fn a_one_use_permission_survives_no_restart_and_no_second_handle() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_400;
    let Company { mut core, person, device, .. } = company(folder.path(), "replay", now);
    let work = work_for(&mut core, &person, &device, now);
    let realm = core.realm().id.clone();
    let claims = Claims::new(&realm, Capability::Models, &person, &device, &work, &work, now, 3_600);
    let first = core.mint(&claims).unwrap();
    let second = core.mint(&Claims::new(&realm, Capability::Models, &person, &device, &work, &work, now, 3_600)).unwrap();

    core.accept(&first, &attempt(&realm, &device, &work), now).unwrap();
    assert!(core.accept(&first, &attempt(&realm, &device, &work), now).unwrap_err().contains("already used"));

    // A restart does not forget it.
    let path = core.path().to_owned();
    core.close().unwrap();
    let mut reopened = Core::open(&path, &key()).unwrap();
    assert!(reopened.accept(&first, &attempt(&realm, &device, &work), now).unwrap_err().contains("already used"));

    // Two handles on one file, and the second one is refused. Each handle keeps its own memory of
    // what it has spent, so only the row in the database can settle this.
    let mut beside = Core::open(&path, &key()).unwrap();
    reopened.accept(&second, &attempt(&realm, &device, &work), now).unwrap();
    let refused = beside.accept(&second, &attempt(&realm, &device, &work), now).unwrap_err();
    assert!(refused.contains("already used"), "a second handle took a permission that was spent: {refused}");

    // And the database itself refuses to unspend it, whatever opens the file.
    let connection = rusqlite::Connection::open(&path).unwrap();
    let refused = connection.execute("UPDATE capabilities SET spent_at = NULL WHERE id = ?1", rusqlite::params![claims.id]).unwrap_err().to_string();
    assert!(refused.contains("cannot be unused"), "{refused}");
}

// ---------------------------------------------------------------------------------------------
// 4. Revocation races
// ---------------------------------------------------------------------------------------------

/// PROVES that a permission minted in the same instant as a withdrawal is refused, that bringing
/// a suspended account back does not revive what it held, and that pausing the grid refuses a
/// permission somebody is already holding and reopening it does not bring that permission back.
///
/// The same-instant arm matters because the comparison is on generations and not on the clock,
/// so there is no window. It is kept as a named regression against somebody later adding one.
///
/// This extends `a_permission_stops_working_when_its_computer_or_account_does` (tests.rs), which
/// covers the ordinary before-and-after case.
///
/// DOES NOT PROVE that withdrawal reaches a connection somebody already has open, or a process
/// already running. The core holds neither. It also does not prove anything about two processes
/// racing: this test is one thread.
#[test]
fn nothing_revives_a_permission_a_withdrawal_killed() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_500;
    let Company { mut core, person, device, .. } = company(folder.path(), "races", now);
    let work = work_for(&mut core, &person, &device, now);
    let realm = core.realm().id.clone();
    let before = core.mint(&Claims::new(&realm, Capability::Models, &person, &device, &work, &work, now, 3_600)).unwrap();

    // Minted and withdrawn in the same instant: still refused, because nothing here is a clock.
    let same = core.mint(&Claims::new(&realm, Capability::Models, &person, &device, &work, &work, now, 3_600)).unwrap();
    core.suspend_principal("owner", &person, "under review", now).unwrap();
    assert!(core.accept(&same, &attempt(&realm, &device, &work), now).unwrap_err().contains("no longer in this grid"));
    assert!(core.accept(&before, &attempt(&realm, &device, &work), now).unwrap_err().contains("no longer in this grid"));

    // Bringing the account back does not lower its generation, so what it held stays dead.
    core.store_for_tests().restore_principal(&person).unwrap();
    assert!(core.principal(&person).unwrap().unwrap().active(), "the account is back");
    assert!(core.accept(&before, &attempt(&realm, &device, &work), now + 1).unwrap_err().contains("no longer in this grid"));
    assert!(core.store_for_tests().generation_for_tests("principals", &person).unwrap() >= 2, "a suspension raised the generation and nothing lowered it");

    // A permission minted after the account came back works, and pausing the grid stops it.
    let after = core.mint(&Claims::new(&realm, Capability::Models, &person, &device, &work, &work, now + 1, 3_600)).unwrap();
    core.set_lifecycle("owner", Lifecycle::Paused, now + 2).unwrap();
    // Refused twice over: a paused grid serves nothing, which is asked first, and pausing raised
    // the policy version, which is what still refuses it once the grid is open again.
    assert!(core.accept(&after, &attempt(&realm, &device, &work), now + 3).unwrap_err().contains("not serving work"));
    core.set_lifecycle("owner", Lifecycle::Open, now + 4).unwrap();
    assert!(core.accept(&after, &attempt(&realm, &device, &work), now + 5).unwrap_err().contains("policy changed"), "reopening does not bring back what pausing stopped");
}

// ---------------------------------------------------------------------------------------------
// 5. Approval bypass
// ---------------------------------------------------------------------------------------------

/// PROVES that an agreement cannot be stretched past the ceiling, shortened to nothing, widened
/// to another method, another path or another person, or used after it has run out, and that a
/// decision written once cannot be written again, updated or deleted, whatever opens the file.
///
/// This extends `an_approver_can_allow_a_credential_for_a_while_unless_it_needs_them_every_time`
/// (tests.rs), which covers the ordinary allowance, and `a_decision_and_the_history_cannot_be_
/// rewritten_in_the_file`, which covers the triggers on the history rather than on the decision.
///
/// DOES NOT PROVE that twenty-four hours is the right ceiling, or that a person cannot hold two
/// accounts. The first is policy and the second is the identity provider's.
#[test]
fn an_agreement_cannot_be_stretched_widened_or_decided_twice() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_600;
    let mut core = Core::create(&folder.path().join("approval.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialAdmin], now).unwrap().id;
    let approver = core.add_principal("owner", PrincipalKind::Person, "Hedy", &[Role::CredentialApprover], now).unwrap().id;
    let user = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::User], now).unwrap().id;
    let (device, _) = core.enrol_device(&user, "Ada's laptop", "windows", now).unwrap();
    let device = device.id;
    let print = fingerprint_of("sk-live-9f2b7c41e8a24d6fb0c3e5a7d91f4b62");
    let realm = core.realm().id.clone();
    let credential = Credential::new(&realm, "Billing", Secret::ApiKey, "yougori-credential-billing", &print, "https://api.acme.test", &admin, now)
        .unwrap()
        .narrowed_to(&["post"], &["/v1/"], Some(4_096));
    let credential = core.add_credential(&admin, credential, now).unwrap();
    core.allow_credential(&admin, &credential.id, &user, &["post"], &["/v1/"], None, now).unwrap();

    // An allowance cannot be longer than the ceiling or shorter than nothing.
    let request = core.ask_for_credential(&user, &credential.id, "POST", "/v1/charge", 600, now).unwrap();
    let ceiling = format!("1 to {} hours", approval::MAX_HOURS);
    assert!(core.decide(&request.id, Action::ApproveCredential, &approver, Verdict::Hours(approval::MAX_HOURS + 1), now).unwrap_err().contains(&ceiling));
    assert!(core.decide(&request.id, Action::ApproveCredential, &approver, Verdict::Hours(0), now).unwrap_err().contains(&ceiling));

    // Granted for one method and one path, it covers that one and nothing beside it.
    let (_, allowance) = core.decide(&request.id, Action::ApproveCredential, &approver, Verdict::Hours(4), now).unwrap();
    let allowance = allowance.expect("agreeing for a while makes a standing allowance");
    assert!(allowance.covers(&user, &credential.id, Some("POST"), Some("/v1/charge"), now));
    for (who, method, path, when) in [
        (user.as_str(), "POST", "/v1/charges", now),
        (user.as_str(), "GET", "/v1/charge", now),
        (admin.as_str(), "POST", "/v1/charge", now),
        (user.as_str(), "POST", "/v1/charge", allowance.expires_at),
    ] {
        assert!(!allowance.covers(who, &credential.id, Some(method), Some(path), when), "the allowance stretched to {who} {method} {path} at {when}");
    }

    // The same request cannot be decided a second time, in Rust or in the file.
    let again = core.decide(&request.id, Action::ApproveCredential, &approver, Verdict::Once, now).unwrap_err();
    assert!(again.contains("already"), "{again}");
    let path = core.path().to_owned();
    let _ = device;
    core.close().unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    for statement in ["UPDATE decisions SET verdict = 'approve_until'", "DELETE FROM decisions"] {
        let refused = connection.execute(statement, []).unwrap_err().to_string();
        assert!(refused.contains("decision cannot be"), "{statement} was allowed: {refused}");
    }
}

// ---------------------------------------------------------------------------------------------
// 6. Audit tampering
// ---------------------------------------------------------------------------------------------

/// PROVES that changing any one of eight fields of a sealed event makes verification name that
/// event, and that recomputing a plain hash chain over the edited events does not repair it,
/// because the seal is an HMAC under a key that is not in the file.
///
/// This extends `a_decision_and_the_history_cannot_be_rewritten_in_the_file` (tests.rs), which
/// covers the reason field alone and the trigger that guards it.
///
/// DOES NOT PROVE detection without the key. Verification needs the realm key, which is the point
/// of sealing rather than hashing, and an attacker who holds that key is out of scope by design.
#[test]
fn an_altered_event_names_itself_whichever_field_was_touched() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_700;
    let Company { mut core, admin, person, .. } = company(folder.path(), "audit", now);
    core.raise_policy(&admin, "a second event", now).unwrap();
    core.grant(&admin, &person, Role::Auditor, now).unwrap();
    let chain = core.store_for_tests().chain().unwrap();
    assert!(chain.events.len() >= 4);
    core.verify_audit().unwrap();

    let touches: Vec<Change<audit::Event>> = vec![
        ("reason", Box::new(|event: &mut audit::Event| event.reason = "rewritten".into())),
        ("at", Box::new(|event: &mut audit::Event| event.at += 1)),
        ("action", Box::new(|event: &mut audit::Event| event.action = "principal.removed".into())),
        ("principalId", Box::new(|event: &mut audit::Event| event.principal_id = "somebody-else".into())),
        ("resourceId", Box::new(|event: &mut audit::Event| event.resource_id = Some("resource-else".into()))),
        ("policyVersion", Box::new(|event: &mut audit::Event| event.policy_version += 1)),
        ("decision", Box::new(|event: &mut audit::Event| event.decision = audit::Decision::Refused)),
        ("previousSeal", Box::new(|event: &mut audit::Event| event.previous_seal = "root".into())),
    ];
    for (field, touch) in touches {
        let mut edited = chain.clone();
        touch(&mut edited.events[2]);
        let broke = edited.verify(&key()).unwrap_err();
        assert!(broke.contains(&format!("Event {}", edited.events[2].sequence)) || broke.contains("chain breaks"), "{field}: {broke}");
    }

    // Somebody who drops the guard, edits an event and recomputes a plain hash chain over the
    // result still cannot make it verify: a plain hash is computable without the key and the
    // seal is not.
    let path = core.path().to_owned();
    core.close().unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("DROP TRIGGER audit_events_never_change").unwrap();
    connection.execute("UPDATE audit_events SET reason = 'nothing happened' WHERE sequence = 2", []).unwrap();
    let repaired: Vec<(i64, String)> = {
        let mut previous = "root".to_owned();
        let mut rows = Vec::new();
        for event in &chain.events {
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(format!("{}{}", event.sequence, previous).as_bytes());
            let seal = hex::encode(hasher.finalize());
            rows.push((event.sequence as i64, seal.clone()));
            previous = seal;
        }
        rows
    };
    for (sequence, seal) in repaired {
        connection.execute("UPDATE audit_events SET seal = ?2 WHERE sequence = ?1", rusqlite::params![sequence, seal]).unwrap();
    }
    drop(connection);
    let reopened = Core::open(&path, &key()).unwrap();
    let broke = reopened.verify_audit().unwrap_err();
    assert!(broke.contains("was altered"), "a chain resealed with a plain hash verified: {broke}");
}

/// PROVES how far the history catches a run of events deleted off an end, which is further than
/// the links alone go and not as far as a reader might assume. A run deleted off the end is
/// caught, because the chain no longer ends where `audit_chain` says it does. A front raised past
/// the export watermark and then deleted is not caught at all, because that is exactly what
/// trimming an exported front does. And somebody who edits `audit_chain` as well as the events
/// defeats both, which this test performs rather than asserts, so the limit is written down here
/// instead of being discovered later.
///
/// The attacker modelled is the one `an_altered_event_names_itself_whichever_field_was_touched`
/// already models: somebody who can write to the file and does not hold the realm key.
///
/// DOES NOT PROVE that a cut-off end can be detected on this computer at all in the worst case.
/// The head and the watermark are columns in the same file as the events, so the only thing that
/// settles an end is a copy that left this computer.
#[test]
fn a_history_cut_off_at_either_end_is_caught_only_so_far() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_750;
    let Company { mut core, admin, person, .. } = company(folder.path(), "cut", now);
    core.raise_policy(&admin, "a second event", now).unwrap();
    core.grant(&admin, &person, Role::Auditor, now).unwrap();
    core.verify_audit().unwrap();
    let path = core.path().to_owned();
    let events = core.since(0).unwrap();
    let last = events.last().unwrap().clone();
    let before_last = events[events.len() - 2].clone();
    core.close().unwrap();

    // The attacker raises the watermark the delete guard consults, which is an ordinary column,
    // and takes the last event away. Every event that is left seals correctly and every link
    // between them holds, so the chain on its own says nothing is wrong.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute_batch(&format!("UPDATE audit_chain SET exported_to = {}; DELETE FROM audit_events WHERE sequence = {};", i64::MAX, last.sequence))
        .unwrap();
    drop(connection);
    let cut = Core::open(&path, &key()).unwrap();
    assert!(cut.store_for_tests().chain().unwrap().verify(&key()).is_ok(), "a chain with its tail cut off is a genuine chain of a shorter history");
    let caught = cut.verify_audit().unwrap_err();
    assert!(caught.contains(&format!("ends at event {}", before_last.sequence)) && caught.contains(&format!("reaching event {}", last.sequence)), "{caught}");
    assert!(cut.check_storage().unwrap().iter().any(|fault| fault.contains("ends at event")), "the same answer when a person asks what is wrong");
    cut.close().unwrap();

    // And the limit, performed rather than described: move the recorded end back to match and the
    // same realm verifies clean, with a run of its history gone and nothing on this computer able
    // to say so.
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection
        .execute("UPDATE audit_chain SET head_sequence = ?1, head_seal = ?2", rusqlite::params![before_last.sequence as i64, before_last.seal])
        .unwrap();
    drop(connection);
    let hidden = Core::open(&path, &key()).unwrap();
    hidden.verify_audit().unwrap();
    assert!(hidden.check_storage().unwrap().is_empty(), "nothing in this file can show an end that was cut off and tidied up after");
}

/// PROVES that no caller-supplied text becomes an unfiltered field of the history: a reason is
/// stripped of control characters and cut to five hundred, a reason that looks like a value is
/// withheld whoever wrote it, and the database itself refuses an identifier longer than an
/// identifier.
///
/// Both layers are here on purpose. `Entry::because` strips and truncates; `Entry::safe`, which
/// `Core::note` calls on every event a realm writes, replaces a value-shaped reason outright.
///
/// DOES NOT PROVE that an identifier names something real. The bound is on length, not on
/// existence, because `Store::put_events` replays an imported chain through the same door and a
/// chain may legitimately name an account that was removed afterwards.
#[test]
fn nothing_a_stranger_sends_becomes_a_field_of_the_history() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_800;
    let Company { mut core, person, device, .. } = company(folder.path(), "reasons", now);
    let work = work_for(&mut core, &person, &device, now);
    let wild = format!("line one\r\nline two\0{}|more", "Z".repeat(10_000));

    core.cancel_work("owner", &work, now).unwrap();
    core.suspend_principal("owner", &person, &wild, now).unwrap();
    core.report_condition(&device, false, 10.0, false, false, now).unwrap();
    for event in core.since(0).unwrap() {
        assert!(event.reason.chars().count() <= 500, "a reason is at most five hundred characters");
        assert!(!event.reason.chars().any(char::is_control), "a reason carries no control character: {:?}", event.reason);
        assert!(!event.reason.contains(['\n', '\r', '\0']), "a reason is one line: {:?}", event.reason);
    }

    // A reason shaped like a value is withheld wherever it came from.
    core.raise_policy("owner", "sk-live-9f2b7c41e8a24d6fb0c3e5a7d91f4b62", now).unwrap();
    let last = core.since(0).unwrap().pop().unwrap();
    assert_eq!(last.reason, "withheld: this reason looked like a value");

    // And the database refuses an identifier that is a sentence, whatever writes it.
    let path = core.path().to_owned();
    let realm = core.realm().id.clone();
    core.close().unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    let refused = connection
        .execute(
            "INSERT INTO audit_events (sequence, id, realm_id, at, principal_id, action, policy_version, decision, previous_seal, seal)
             VALUES (9999, 'event-made-up', ?1, 1, ?2, 'made.up', 1, 'allowed', 'root', 'seal')",
            rusqlite::params![realm, "Q".repeat(10_000)],
        )
        .unwrap_err()
        .to_string();
    assert!(refused.contains("identifier in the history is an identifier"), "{refused}");
}

// ---------------------------------------------------------------------------------------------
// 7. Backup tampering
// ---------------------------------------------------------------------------------------------

/// PROVES that a backup edited after it was taken is refused whichever part was edited: the
/// header, including the three fields that travel beside the record rather than in it, a row of
/// state, or the history. The header and the state are sealed with the realm's key exactly as each
/// event is, so adding an administrator to a backup and leaving the chain alone no longer survives
/// a restore, and neither does moving where a restored realm would look for its key.
///
/// This is the fix for what would otherwise have been a finding: before it, a backup's history
/// was sealed and its state was not, so anybody who could edit one file could restore themselves
/// into a realm with the chain still verifying.
///
/// DOES NOT PROVE anything against somebody who holds the realm key. They can seal whatever they
/// like, and the threat model says so. It also does not prove a backup is kept safely; where the
/// file goes is the deployment's business.
#[test]
fn a_backup_edited_after_it_was_taken_is_refused_whichever_part_was_edited() {
    let folder = tempfile::tempdir().unwrap();
    let now = 40_900;
    let Company { mut core, admin, person, .. } = company(folder.path(), "backup", now);
    core.grant(&admin, &person, Role::Auditor, now).unwrap();
    let taken = core.backup(now).unwrap();
    assert!(!taken.record_seal.is_empty(), "a backup carries a seal over what it holds");

    // An added administrator, with the history left exactly as it was.
    let mut added = taken.clone();
    let mut intruder = added.record.principals[0].clone();
    intruder.id = "principal-intruder".into();
    intruder.name = "Intruder".into();
    intruder.roles = vec![Role::RealmAdmin];
    added.record.principals.push(intruder);
    assert!(added.record.audit.verify(&key()).is_ok(), "the history is untouched, which is the whole point of this attack");
    let refused = Core::restore(&folder.path().join("added.db"), added, &key()).unwrap_err();
    assert!(refused.contains("do not match its seal"), "{refused}");

    // A seal removed altogether is a refusal, not a pass.
    let mut stripped = taken.clone();
    stripped.record_seal = String::new();
    assert!(Core::restore(&folder.path().join("stripped.db"), stripped, &key()).unwrap_err().contains("do not match its seal"));

    // A header swapped for another realm's, and a backup claiming to be from a newer build.
    let mut swapped = taken.clone();
    swapped.key_fingerprint = crate::digest("realm-key", &other_key());
    assert!(Core::restore(&folder.path().join("swapped.db"), swapped, &key()).unwrap_err().contains("not this grid's key"));

    // The three header fields that travel beside the record rather than in it. A restored realm
    // reads `key_id` and `key_version` back as where to find the key that opens it, so a backup
    // that said somewhere else would leave a correct realm nobody could open unattended. The seal
    // is over these as well as over the state, which is what makes the name of this test true.
    for (what, edit) in [
        ("key_id", Box::new(|backup: &mut store::Backup| backup.key_id = "yougori-core-some-other-realm".into()) as Box<dyn Fn(&mut store::Backup)>),
        ("key_version", Box::new(|backup: &mut store::Backup| backup.key_version += 1)),
        ("taken_at", Box::new(|backup: &mut store::Backup| backup.taken_at -= 86_400)),
    ] {
        let mut edited = taken.clone();
        edit(&mut edited);
        let refused = Core::restore(&folder.path().join(format!("{what}.db")), edited, &key()).unwrap_err();
        assert!(refused.contains("do not match its seal"), "{what}: {refused}");
    }
    let mut newer = taken.clone();
    newer.schema_version = store::SCHEMA_VERSION + 1;
    assert!(Core::restore(&folder.path().join("newer.db"), newer, &key()).unwrap_err().contains("newer Yougori"));

    // A history edited before the backup was taken passes the seal, which is over what was taken,
    // and fails verification, which is what verification is for.
    let path = core.path().to_owned();
    core.close().unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("DROP TRIGGER audit_events_never_change").unwrap();
    connection.execute("UPDATE audit_events SET reason = 'rewritten' WHERE sequence = 1", []).unwrap();
    drop(connection);
    let spoiled = Core::open(&path, &key()).unwrap().backup(now).unwrap();
    let refused = Core::restore(&folder.path().join("spoiled.db"), spoiled, &key()).unwrap_err();
    assert!(refused.contains("does not verify"), "{refused}");

    // And the honest one restores.
    let restored = Core::restore(&folder.path().join("good.db"), taken, &key()).unwrap();
    assert_eq!(restored.snapshot().unwrap().principals.len(), 2);
}

/// PROVES that a restored realm honours no permission it handed out before the backup was taken,
/// because the permissions it remembers issuing are not part of what a backup carries.
///
/// This overlaps `a_restored_grid_refuses_every_permission_it_handed_out_before` in the broker's
/// tests, which proves the same thing for a credential permission. This one is the model path,
/// which has no broker record to fall back on.
///
/// DOES NOT PROVE a restore is safe in every other way. It proves one property of one.
#[test]
fn a_restored_realm_honours_no_permission_it_handed_out_before_the_backup() {
    let folder = tempfile::tempdir().unwrap();
    let now = 41_000;
    let Company { mut core, person, device, .. } = company(folder.path(), "restored", now);
    let work = work_for(&mut core, &person, &device, now);
    let realm = core.realm().id.clone();
    let token = core.mint(&Claims::new(&realm, Capability::Models, &person, &device, &work, &work, now, 3_600)).unwrap();
    let taken = core.backup(now).unwrap();

    let mut restored = Core::restore(&folder.path().join("again.db"), taken, &key()).unwrap();
    let refused = restored.accept(&token, &attempt(&realm, &device, &work), now + 1).unwrap_err();
    assert!(refused.contains("no record of issuing"), "{refused}");
    restored.verify_audit().unwrap();
}

// ---------------------------------------------------------------------------------------------
// 8. Credential leakage
// ---------------------------------------------------------------------------------------------

/// PROVES that four shapes of secret never reach the realm's database, its journal, a backup, an
/// error message, or the debug output of the realm. What is written is the name of the vault
/// entry, which is a name.
///
/// This extends `a_credential_is_a_reference_and_never_a_value` and `credentials_come_through_a_
/// restart_and_a_backup_with_no_value_in_either` (tests.rs) with the error-message and debug
/// arms, and with the three further secret shapes.
///
/// DOES NOT PROVE that a secret never reaches this process's memory. The broker reads one on
/// purpose, holds it for the length of one request and wipes what it owns; the HTTP library's
/// buffer, the TLS record and the kernel's socket buffer are copies nobody here can reach. Nor
/// does it prove anything about a log the embedding process writes: the core writes no log.
#[test]
fn no_shape_of_a_secret_reaches_a_file_an_error_or_a_printout() {
    let folder = tempfile::tempdir().unwrap();
    let now = 41_100;
    let secrets = [
        "sk-live-9f2b7c41e8a24d6fb0c3e5a7d91f4b62".to_owned(),
        "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBg\n-----END PRIVATE KEY-----".to_owned(),
        "Server=db;User Id=sa;password=Tr0ub4dor&3;".to_owned(),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [7u8; 48]),
    ];
    let mut core = Core::create(&folder.path().join("leak.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialAdmin], now).unwrap().id;
    let realm = core.realm().id.clone();

    for (number, secret) in secrets.iter().enumerate() {
        let print = fingerprint_of(secret);
        // Every place a reference belongs refuses the value, and the refusal does not quote it.
        for refused in [
            Credential::new(&realm, "Billing", Secret::ApiKey, secret, &print, "https://api.acme.test", &admin, now).unwrap_err(),
            Credential::new(&realm, "Billing", Secret::ApiKey, "yougori-credential-billing", secret, "https://api.acme.test", &admin, now).unwrap_err(),
            Credential::new(&realm, secret, Secret::ApiKey, "yougori-credential-billing", &print, "https://api.acme.test", &admin, now).unwrap_err(),
        ] {
            assert!(!refused.contains(secret.as_str()), "a refusal quoted the value: {refused}");
        }
        let credential = Credential::new(&realm, &format!("Billing {number}"), Secret::ApiKey, &format!("yougori-credential-{number}"), &print, "https://api.acme.test", &admin, now).unwrap();
        core.add_credential(&admin, credential, now).unwrap();
        // A reason shaped like a value is withheld rather than sealed.
        core.raise_policy("owner", secret, now).unwrap();
    }

    let printed = format!("{core:?}");
    assert!(!printed.contains(&key()), "the realm's debug output never carries its key");
    let backup = serde_json::to_string(&core.backup(now).unwrap()).unwrap();
    let path = core.path().to_owned();
    core.close().unwrap();
    let bytes = on_disk(&path);
    for secret in &secrets {
        assert!(!holds(&bytes, secret.as_bytes()), "a value reached the database or its journal");
        assert!(!backup.contains(secret.as_str()), "a value reached a backup");
        assert!(!printed.contains(secret.as_str()), "a value reached a printout");
    }
    // The name of the entry did reach it, which is what a reference is for.
    assert!(holds(&bytes, b"yougori-credential-0"));
}

/// PROVES that what a workload is handed for a credential is a permission naming one credential,
/// one destination, one method, one path and a size, that it is for one use, and that nothing in
/// it says where the value is or what it hashes to.
///
/// DOES NOT PROVE that the broker honours it. The broker's own tests do that, over a loopback
/// server, and `a_request_to_another_destination_is_never_sent` is the nearest of them.
#[test]
fn what_a_workload_gets_is_a_permission_and_it_names_one_destination() {
    let folder = tempfile::tempdir().unwrap();
    let now = 41_200;
    let mut core = Core::create(&folder.path().join("permission.db"), "Acme", RealmKind::Primary, &[Capability::Models, Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialAdmin], now).unwrap().id;
    let approver = core.add_principal("owner", PrincipalKind::Person, "Hedy", &[Role::CredentialApprover], now).unwrap().id;
    let user = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::User], now).unwrap().id;
    let (device, _) = core.enrol_device(&user, "Ada's laptop", "windows", now).unwrap();
    let device = device.id;
    let print = fingerprint_of("sk-live-9f2b7c41e8a24d6fb0c3e5a7d91f4b62");
    let realm = core.realm().id.clone();
    let credential = Credential::new(&realm, "Billing", Secret::ApiKey, "yougori-credential-billing", &print, "https://api.acme.test", &admin, now)
        .unwrap()
        .narrowed_to(&["post"], &["/v1/"], Some(4_096));
    let credential = core.add_credential(&admin, credential, now).unwrap();
    core.allow_credential(&admin, &credential.id, &user, &["post"], &["/v1/"], None, now).unwrap();
    let request = core.ask_for_credential(&user, &credential.id, "POST", "/v1/charge", 600, now).unwrap();
    core.decide(&request.id, Action::ApproveCredential, &approver, Verdict::Once, now).unwrap();
    let work = work_for(&mut core, &user, &device, now);

    let token = core.use_credential(&user, &device, &work, &credential.id, "POST", "/v1/charge", 300, now).unwrap();
    let claims = Authority::peek(&token).expect("a permission reads back");
    assert_eq!(claims.capability, Capability::Credentials);
    assert_eq!(claims.resource_id, credential.id);
    assert_eq!(claims.destination.as_deref(), Some("https://api.acme.test"));
    assert_eq!(claims.method.as_deref(), Some("POST"));
    assert_eq!(claims.path.as_deref(), Some("/v1/charge"));
    assert_eq!(claims.maximum_bytes, Some(4_096));
    assert!(claims.single_use, "a permission to use a credential is for one use");
    let printed = serde_json::to_string(&claims).unwrap();
    assert!(!printed.contains("yougori-credential-billing"), "the permission says where the value is: {printed}");
    assert!(!printed.contains(print.as_str()), "the permission carries the fingerprint: {printed}");

    // One agreement, one permission. Asking again is refused.
    assert!(core.use_credential(&user, &device, &work, &credential.id, "POST", "/v1/charge", 300, now).unwrap_err().contains("agree to this use first"));
}

// ---------------------------------------------------------------------------------------------
// 9. Prompt leakage
// ---------------------------------------------------------------------------------------------

/// PROVES that no table in a realm carries a column NAMED for a prompt, an answer, a system
/// message or anything else from inside a workspace, so a table added later is caught by the same
/// rule. It also proves that the one free-text column a workload does carry, `workloads.note`, is
/// stripped of control characters and cut to three hundred on the way in, whoever filled it in.
///
/// This extends the existing checks, which look at the seven workspace tables and the model path,
/// to every table the database has.
///
/// DOES NOT PROVE what any column holds. A column name is vocabulary and not content, and this
/// reads names. `model_requests_use_the_plan_assignment_and_never_store_the_prompt` and the byte
/// scan in `tests.rs` are what show it for the model path, and the bound asserted below is what
/// keeps the claim true for a path somebody adds later. It proves nothing about a model's
/// behaviour, and nothing in this work attempts to change one. What the runtime writes outside the
/// realm's database is the runtime's own business.
#[test]
fn no_table_in_a_realm_has_a_column_that_could_hold_a_prompt_or_a_desks_contents() {
    let folder = tempfile::tempdir().unwrap();
    let now = 41_300;
    let Company { mut core, person, device, .. } = company(folder.path(), "prompts", now);

    // The column a workload does carry free text in. An embedder that put what somebody typed in
    // it would otherwise have written it verbatim and unbounded into the realm, where it survives
    // every backup and every snapshot, and the column-name rule above cannot see that at all.
    let realm = core.realm().id.clone();
    let version = core.store_for_tests().policy_version().unwrap();
    let needs = Resources { cpu: 1.0, memory_gb: 1.0, disk_gb: 1.0, gpu: false, vram_gb: 0.0 };
    let mut typed = Workload::new(&realm, Capability::Models, Kind::Inference, &person, &device, needs, version, now);
    typed.note = Some(format!("summarise\tthis\nfor me: {}", "a".repeat(2_000)));
    let placed = core.submit(typed, now).unwrap();
    let kept = placed.note.clone().unwrap();
    assert_eq!(kept.chars().count(), 300, "the note a caller filled in is cut to three hundred");
    assert!(!kept.chars().any(char::is_control), "and carries no control character: {kept:?}");
    let stored: String = core
        .store_for_tests()
        .connection_for_tests()
        .query_row("SELECT note FROM workloads WHERE id = ?1", rusqlite::params![placed.id], |row| row.get(0))
        .unwrap();
    assert_eq!(stored, kept, "what the queue took is what the file holds");

    // The one caller that uses the column on purpose still fits inside the bound: eleven
    // characters of prefix, a twenty-seven character plan name, a colon, and a model name
    // `validate_model` already holds to two hundred bytes.
    let longest = "model-plan:".len() + "model-plan-0123456789abcdef".len() + ":".len() + 200;
    assert!(longest <= 300, "a model request is {longest} characters and the bound is three hundred");
    let forbidden = [
        "prompt", "prompts", "completion", "response_body", "answer", "system_message", "messages", "transcript", "content", "payload", "body", "document",
        "file_bytes", "blob", "screenshot", "keystrokes", "clipboard", "secret", "value", "password", "plaintext",
    ];
    let mut tables = core
        .store_for_tests()
        .connection_for_tests()
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .unwrap()
        .query_map([], |row| row.get::<_, String>(0))
        .unwrap()
        .collect::<rusqlite::Result<Vec<_>>>()
        .unwrap();
    tables.sort();
    assert!(tables.len() > 20, "a realm has more than twenty tables; this would be checking nothing otherwise");
    for table in &tables {
        let columns: Vec<String> = core
            .store_for_tests()
            .connection_for_tests()
            .prepare(&format!("SELECT name FROM pragma_table_info('{table}')"))
            .unwrap()
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap();
        for column in columns {
            assert!(!forbidden.contains(&column.as_str()), "{table}.{column} could hold something a realm must never keep");
        }
    }
}

/// PROVES that the words sealed into the history when a computer gives work back are chosen here
/// and not by the computer: `Setback` is a closed enum and every one of its five sentences is
/// fixed in this crate.
///
/// DOES NOT PROVE that every path writes a closed enum. Several take free text on purpose, and
/// `nothing_a_stranger_sends_becomes_a_field_of_the_history` is what bounds those.
#[test]
fn a_computer_that_gives_work_back_never_chooses_the_words() {
    let folder = tempfile::tempdir().unwrap();
    let now = 41_400;
    let Company { mut core, person, device, .. } = company(folder.path(), "setbacks", now);
    let said: Vec<&'static str> = [Setback::WentQuiet, Setback::Busy, Setback::ModelNotReady, Setback::Unusable, Setback::LeftTheGrid].iter().map(|setback| setback.say()).collect();

    for setback in [Setback::WentQuiet, Setback::Busy, Setback::ModelNotReady, Setback::Unusable, Setback::LeftTheGrid] {
        let work = work_for(&mut core, &person, &device, now);
        let lease = core.grant_lease(&work, 600, now).unwrap();
        core.give_back(&lease.id, setback, now).unwrap();
    }
    let reasons: Vec<String> = core.since(0).unwrap().into_iter().filter(|event| event.action.starts_with("work.")).map(|event| event.reason).collect();
    for reason in reasons.iter().filter(|reason| !reason.is_empty()) {
        assert!(said.contains(&reason.as_str()) || reason == "the computer did not finish in time", "a reason nobody in this crate wrote: {reason}");
    }
}

// ---------------------------------------------------------------------------------------------
// 10. Host impersonation
// ---------------------------------------------------------------------------------------------

/// PROVES that a computer cannot report on, adopt or park a workspace that is not its own, that a
/// computer cannot offer more than it has, and that what a computer was committed to cannot be
/// rewritten by offering again or by editing the file.
///
/// DOES NOT PROVE that the computer identifier was authenticated. The core takes it as text and
/// trusts its caller, which is the single most important thing this phase has to say: `Core::
/// authenticate` exists and no other method in the core calls it. It also does not prove the
/// capacity a computer declares is real; a computer reports its own size.
#[test]
fn a_computer_cannot_speak_for_another_or_rewrite_what_it_committed_to() {
    let folder = tempfile::tempdir().unwrap();
    let now = 41_500;
    let Company { mut core, admin, person, device, host } = company(folder.path(), "hosts", now);
    let second = core.add_principal(&admin, PrincipalKind::Person, "Mary", &[Role::Operator], now).unwrap();
    let (stranger, _) = core.enrol_device(&second.id, "Mary's laptop", "linux", now).unwrap();
    core.offer_host(&stranger.id, "Render PC", big(), big(), Commitment::Share, now).unwrap();

    // A computer cannot offer more than it has.
    let more = Resources { cpu: 64.0, memory_gb: 512.0, disk_gb: 4_000.0, gpu: true, vram_gb: 80.0 };
    assert!(core.offer_host(&device, "Studio PC", big(), more, Commitment::Share, now).unwrap_err().contains("cannot offer more than it has"));

    // What it was committed to is a decision somebody made, and offering again does not change it.
    core.commit_host(&admin, &host, Commitment::Dedicated, big(), false, now).unwrap();
    let again = core.offer_host(&device, "Studio PC", big(), big(), Commitment::Share, now + 1).unwrap();
    assert_eq!(again.commitment, Commitment::Dedicated, "an offer cannot rewrite a commitment");
    assert_eq!(again.id, host, "and a computer that offers again keeps its place");

    // A workspace reported on by a computer that does not hold it is refused.
    let built = image(&mut core, &admin, now);
    let quota = workspace::Quota::for_disk(10.0).unwrap();
    let workspace = core.order_workspace(&admin, "Ada's desk", &built.id, workspace::Access::Standard, quota, Some(&person), now).unwrap();
    core.report_condition(&device, false, 500.0, false, false, now).unwrap();
    core.place_workspace(&admin, &workspace.id, 600, now).unwrap();
    let claim = claim_for(&core, &workspace.id);
    let lie = workspace::Claim::new(&workspace.id, claim.workspace_generation, claim.assignment_generation, "host-somewhere-else");
    let refused = core.report_workspace(&stranger.id, &claim, workspace::Report::new(workspace::Reported::Ready), now).unwrap_err();
    assert!(refused.contains("not this computer's workspace"), "{refused}");
    assert!(core.report_workspace(&device, &lie, workspace::Report::new(workspace::Reported::Ready), now).is_err(), "a computer cannot name another computer's workspace");
    assert!(core.adopt_workspace(&stranger.id, &claim, now).is_err());

    // And the file itself refuses to rewrite a commitment.
    let path = core.path().to_owned();
    core.close().unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    let refused = connection.execute("UPDATE host_commitments SET commitment = 'none'", []).unwrap_err().to_string();
    assert!(refused.contains("recorded as it was") || refused.contains("never change") || refused.contains("agreed"), "{refused}");
}

// ---------------------------------------------------------------------------------------------
// 11. Worker escape
// ---------------------------------------------------------------------------------------------

/// PROVES the part of worker escape that this repository can check: a permission reaches only the
/// resource it names, a permission for one kind of thing is refused by the door for another, and
/// an artifact key can never be a place on a computer, refused by Rust and refused again by the
/// database when Rust is bypassed.
///
/// WHAT REMAINS UNPROVEN, IN WORDS. Escaping a container, a microVM or a virtual machine is a
/// property of a hypervisor and a kernel, not of this code. The realm holds a kind and an opaque
/// reference to where a workspace was placed and nothing else, so there is no boundary here to
/// attack. Proving containment would mean starting real sandboxes on this computer, which this
/// work does not do. Nothing below should be read as evidence that a compromised workload cannot
/// reach the host it runs on; it is evidence that it cannot reach another realm's resources
/// through the realm's own doors.
#[test]
fn a_permission_reaches_only_what_it_names_and_an_artifact_key_is_never_a_place_on_a_computer() {
    let folder = tempfile::tempdir().unwrap();
    let now = 41_600;
    let Company { mut core, admin, person, device, host } = company(folder.path(), "escape", now);
    let realm = core.realm().id.clone();
    let first = work_for(&mut core, &person, &device, now);
    let second = work_for(&mut core, &person, &device, now);

    // A permission for one piece of work is refused for another.
    let token = core.mint(&Claims::new(&realm, Capability::Models, &person, &device, &first, &first, now, 600)).unwrap();
    let refused = core.accept(&token, &attempt(&realm, &device, &second), now).unwrap_err();
    assert!(refused.contains("does not allow that piece of work"), "{refused}");

    // A permission for a model is refused by the door for a workspace.
    let built = image(&mut core, &admin, now);
    let quota = workspace::Quota::for_disk(10.0).unwrap();
    let workspace = core.order_workspace(&admin, "Ada's desk", &built.id, workspace::Access::Standard, quota, Some(&person), now).unwrap();
    let wrong = core.mint(&Claims::new(&realm, Capability::Models, &person, &device, &first, &workspace.id, now, 600)).unwrap();
    let refused = core.use_workspace(&wrong, &Attempt { realm_id: &realm, device_id: &device, workload_id: &first, resource_id: &workspace.id, ..Default::default() }, now).unwrap_err();
    assert!(refused.contains("not for a workspace"), "{refused}");

    // An artifact key is a key, not a path. Rust refuses each of these, and so does the database
    // when Rust is bypassed, so neither is the only line.
    let long = "k".repeat(1_025);
    let shapes = ["/etc/passwd", "C:\\keys\\id_rsa", "..\\..\\x", "a/../../b", "a\\b", "", long.as_str()];
    for shape in shapes {
        assert!(
            workspace::Artifact::new(&workspace, workspace::ArtifactStore::Bucket, "s3://parked", shape, 10, &"0".repeat(64), &host, now).is_err(),
            "Artifact::new took {shape:?} as a key"
        );
    }
    let path = core.path().to_owned();
    core.close().unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    for (number, shape) in shapes.iter().enumerate() {
        let refused = connection.execute(
            "INSERT INTO workspace_artifacts (id, realm_id, workspace_id, workspace_gen, store, destination, object_key, bytes, sha256, packed_by, packed_at)
             VALUES (?1, ?2, ?3, 1, 'bucket', 's3://parked', ?4, 10, ?5, ?6, 1)",
            rusqlite::params![format!("artifact-{number}"), realm, workspace.id, shape, "0".repeat(64), host],
        );
        assert!(refused.is_err(), "the database took {shape:?} as an artifact key");
    }
}

/// PROVES that a research realm has no door to a credential at all, and that the refusal is on
/// the realm's capability rather than on a role, so granting somebody every role in the realm
/// does not open it.
///
/// This extends `a_research_realm_reaches_no_credential_and_no_permission_crosses_between_realms`
/// in the broker's tests by checking the order of the refusal rather than only its presence.
///
/// DOES NOT PROVE containment of a research workload. There is no worker here and none may be
/// started: this is about which doors exist, not about what runs behind them.
#[test]
fn a_research_realm_has_no_door_to_a_credential_whatever_role_is_granted() {
    let folder = tempfile::tempdir().unwrap();
    let now = 41_700;
    let mut core = Core::create(&folder.path().join("study.db"), "Study", RealmKind::Research, &[Capability::Research], &key(), now).unwrap();
    let scholar = core
        .add_principal("owner", PrincipalKind::Person, "Grace", &[Role::RealmAdmin, Role::CredentialAdmin, Role::CredentialApprover, Role::SecurityAdmin], now)
        .unwrap()
        .id;
    let (device, _) = core.enrol_device(&scholar, "Grace's laptop", "linux", now).unwrap();
    let device = device.id;
    let print = fingerprint_of("sk-live-9f2b7c41e8a24d6fb0c3e5a7d91f4b62");
    let realm = core.realm().id.clone();

    // The two doors that take a credential in or hand one out refuse on the realm's own
    // capability, before any permission is consulted, so holding every role in the realm does not
    // open either of them.
    let credential = Credential::new(&realm, "Billing", Secret::ApiKey, "yougori-credential-billing", &print, "https://api.acme.test", &scholar, now).unwrap();
    assert!(core.add_credential(&scholar, credential, now).unwrap_err().contains("broker credentials"));
    assert!(core.use_credential(&scholar, &device, "work-none", "credential-none", "POST", "/v1/charge", 60, now).unwrap_err().contains("broker credentials"));

    // The three that act on a credential already in the realm do not ask the realm's capability
    // at all. They refuse because there is nothing to act on, and in a research realm there never
    // can be: the database itself refuses the row. That is worth being plain about rather than
    // dressing up. It is not reachable, because the only ways in are shut, but the gate on those
    // three is the database and not the Rust above it.
    for refused in [
        core.allow_credential(&scholar, "credential-none", &scholar, &["post"], &["/v1/"], None, now).unwrap_err(),
        core.rotate_credential(&scholar, "credential-none", &"0".repeat(64), now).unwrap_err(),
        core.retire_credential(&scholar, "credential-none", now).unwrap_err(),
    ] {
        assert!(refused.contains("No such credential") || refused.contains("no credential"), "{refused}");
    }
    let refused = core
        .store_for_tests()
        .connection_for_tests()
        .execute(
            "INSERT INTO credentials (id, realm_id, name, kind, vault_id, vault_version, fingerprint, destination, methods, paths, maximum_bytes, owner_id, every_time, created_at, rotated_at, rotate_by, retired_at, generation, presentation, field)
             VALUES ('credential-smuggled', ?1, 'Billing', 'apiKey', 'yougori-credential-billing', 1, ?2, 'https://api.acme.test', '[]', '[]', NULL, ?3, 0, 1, NULL, NULL, NULL, 1, 'bearer', '')",
            rusqlite::params![realm, print, scholar],
        )
        .unwrap_err()
        .to_string();
    assert!(refused.contains("research") || refused.contains("credential"), "a credential was written into a research realm: {refused}");

    // And the realm is offline by default, so there is nowhere to send one in any case.
    assert_eq!(core.realm().network, NetworkPolicy::offline());
}

// ---------------------------------------------------------------------------------------------
// 12. Network pivoting
// ---------------------------------------------------------------------------------------------

/// PROVES that an offline realm allows no destination at all, that a company realm with a list
/// allows only what is on it, that a credential names one HTTPS place and refuses a plain
/// address, a bare host and a URL with a password in it, and that a permission minted for one
/// place is refused for another.
///
/// DOES NOT PROVE that a workload obeys any of it. Nothing in the core enforces a network rule on
/// a running process; the sandbox does that, and this repository cannot test the sandbox. It also
/// proves nothing about where a name resolves to or whether TLS was verified: the forwarder does
/// that work, its tests run against a loopback server, and no test here or there reaches a live
/// address.
#[test]
fn an_offline_realm_allows_nothing_and_a_credential_names_one_place() {
    let folder = tempfile::tempdir().unwrap();
    let now = 41_800;
    let offline = NetworkPolicy::offline();
    for destination in ["", "https://api.acme.test", "http://10.0.0.8:8080", "anything at all"] {
        assert!(!offline.allows(destination), "an offline realm allowed {destination}");
    }
    let open = NetworkPolicy::company();
    assert!(open.allows("https://api.acme.test"), "a company realm with no list allows anywhere");
    let listed = NetworkPolicy { outbound: true, destinations: vec!["https://api.acme.test".into()], published: false };
    assert!(listed.allows("https://api.acme.test"));
    assert!(!listed.allows("https://api.evil.test"));

    let mut core = Core::create(&folder.path().join("pivot.db"), "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::CredentialAdmin], now).unwrap().id;
    let realm = core.realm().id.clone();
    let print = fingerprint_of("sk-live-9f2b7c41e8a24d6fb0c3e5a7d91f4b62");
    for bad in ["http://api.acme.test", "api.acme.test", "https://user:pass@api.acme.test", "ftp://api.acme.test"] {
        assert!(Credential::new(&realm, "Billing", Secret::ApiKey, "yougori-credential-billing", &print, bad, &admin, now).is_err(), "a credential took {bad} as a place");
    }

    // A research realm is offline the moment it is made, without anybody choosing it.
    let study = Core::create(&folder.path().join("study.db"), "Study", RealmKind::Research, &[Capability::Research], &other_key(), now).unwrap();
    assert!(!study.realm().network.outbound, "a research realm starts offline");
    assert!(!study.realm().network.published, "and is not published");
}
