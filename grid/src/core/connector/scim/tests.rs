//! SCIM 2.0, against a directory on this computer that answers the way RFC 7644 describes.
//!
//! This is the one connector in this phase that changes anything, so it is the one where the rules
//! of the seam have to be shown rather than only the request shapes: the plan is checked before
//! anything moves, carrying it out twice leaves the directory where carrying it out once left it,
//! and every change can be undone.
//!
//! What it does not prove is that Okta, Entra ID or anybody else's SCIM server behaves this way.
//! The standard leaves several of these answers to the implementation, which is exactly why this
//! connector reads the group before it writes to it.
use super::super::wire::{Keyed, Keys, Opened, Present};
use super::super::{Change, Checked, Connector, Request, Settings, Subject, Ticket, Trouble, CHECKED_FOR};
use super::*;
use crate::core::capability::{Authority, Claims};
use crate::core::realm::Capability;
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

fn key() -> String {
    "e".repeat(64)
}

fn permission(credential_id: &str, destination: &str, now: i64) -> Ticket {
    let claims = Claims::new("realm-1", Capability::Credentials, "principal-ada", "device-ada", "work-1", credential_id, now, 3_600).bound_to(destination, "POST", "/", 1 << 20);
    Ticket::read(&Authority::new("realm-1", &key()).mint(&claims).unwrap(), now).unwrap()
}

fn ada() -> Subject {
    Subject::new("ada@acme.example", "Ada").unwrap()
}

struct Vault;

impl Keys for Vault {
    fn open(&self, credential_id: &str) -> Result<Opened, String> {
        if credential_id == "credential-scim" {
            Ok(Opened { fields: json!({"token": "a-directory-token"}), version: 3 })
        } else {
            Err(format!("No credential called {credential_id} is in this computer's vault"))
        }
    }
}

#[derive(Clone, Debug)]
struct Call {
    method: String,
    path: String,
    authorization: String,
    body: String,
}

type Calls = Arc<Mutex<Vec<Call>>>;

/// A SCIM server on loopback, holding one group and two people.
///
/// It answers an add for somebody who is already a member with 204, which is one of the two things
/// a real server may do, precisely so that the connector cannot be written to rely on a conflict.
async fn directory() -> (String, Calls, Arc<Mutex<BTreeSet<String>>>) {
    directory_that(true).await
}

/// The same server, or with `lists_members` false a server of the other kind: it never lists a
/// group's members when the group is read, which RFC 7643 allows (an unassigned attribute is left
/// out, and a server may return only some attributes), and it answers a removal that matches
/// nobody with 400 `noTarget`, as RFC 7644 section 3.5.2 describes for a path that yields nothing.
async fn directory_that(lists_members: bool) -> (String, Calls, Arc<Mutex<BTreeSet<String>>>) {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, Request as HyperRequest, Response};
    use hyper_util::rt::TokioIo;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let calls: Calls = Arc::default();
    let members: Arc<Mutex<BTreeSet<String>>> = Arc::default();
    let (recorder, held) = (calls.clone(), members.clone());
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { break };
            let (recorder, held) = (recorder.clone(), held.clone());
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: HyperRequest<Incoming>| {
                    let (recorder, held) = (recorder.clone(), held.clone());
                    async move {
                        let method = request.method().to_string();
                        let path = request.uri().path_and_query().map(|path| path.to_string()).unwrap_or_default();
                        let authorization = request.headers().get("authorization").and_then(|value| value.to_str().ok()).unwrap_or_default().to_owned();
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        let body = String::from_utf8_lossy(&bytes).into_owned();
                        recorder.lock().unwrap().push(Call { method: method.clone(), path: path.clone(), authorization: authorization.clone(), body: body.clone() });

                        let (status, answer) = if authorization != "Bearer a-directory-token" {
                            (401, json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": "Unauthorized", "status": "401"}))
                        } else if method == "GET" && path.starts_with("/Users?") && path.contains("garbled%40acme.example") {
                            // A 2xx that is not a list of people at all, as a proxy's page or a broken body is.
                            (200, json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"]}))
                        } else if method == "GET" && path.starts_with("/Users?") && path.contains("quiet%40acme.example") {
                            // Nobody found, with `Resources` left out as RFC 7644 allows when there are none.
                            (200, json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": 0}))
                        } else if method == "GET" && path.starts_with("/Users?") && path.contains("hollow%40acme.example") {
                            // Somebody found, by its own count, with nobody in the list.
                            (200, json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": 1, "Resources": []}))
                        } else if method == "GET" && path.starts_with("/Users?") {
                            let found: Vec<serde_json::Value> = if path.contains("ada%40acme.example") {
                                vec![json!({"id": "u-ada", "userName": "ada@acme.example"})]
                            } else if path.contains("twins%40acme.example") {
                                vec![json!({"id": "u-one", "userName": "twins@acme.example"}), json!({"id": "u-two", "userName": "twins@acme.example"})]
                            } else {
                                Vec::new()
                            };
                            (200, json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"], "totalResults": found.len(), "Resources": found}))
                        } else if method == "GET" && path == "/Groups/g-finance" {
                            let members: Vec<serde_json::Value> = held.lock().unwrap().iter().map(|id| json!({"value": id, "type": "User"})).collect();
                            if lists_members {
                                (200, json!({"id": "g-finance", "displayName": "Finance desks", "members": members}))
                            } else {
                                (200, json!({"id": "g-finance", "displayName": "Finance desks"}))
                            }
                        } else if method == "PATCH" && path == "/Groups/g-finance" {
                            let operation = &serde_json::from_str::<serde_json::Value>(&body).unwrap_or(serde_json::Value::Null)["Operations"][0];
                            let op = operation["op"].as_str().unwrap_or_default().to_owned();
                            if op == "add" {
                                let who = operation["value"][0]["value"].as_str().unwrap_or_default().to_owned();
                                // A server that answers an add for an existing member with 204 is
                                // one of the two kinds the standard allows, and the connector must
                                // behave the same against either.
                                held.lock().unwrap().insert(who);
                                (204, serde_json::Value::Null)
                            } else {
                                let path = operation["path"].as_str().unwrap_or_default().to_owned();
                                let who = path.split('"').nth(1).unwrap_or_default().to_owned();
                                let removed = held.lock().unwrap().remove(&who);
                                if removed || lists_members {
                                    (204, serde_json::Value::Null)
                                } else {
                                    (400, json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "scimType": "noTarget", "detail": "No member matched that path", "status": "400"}))
                                }
                            }
                        } else {
                            (404, json!({"schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"], "detail": format!("no route {method} {path}"), "status": "404"}))
                        };
                        Ok::<_, std::convert::Infallible>(
                            Response::builder().status(status).header("content-type", "application/scim+json").body(Full::new(bytes::Bytes::from(answer.to_string()))).unwrap(),
                        )
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
            });
        }
    });
    (format!("http://{address}"), calls, members)
}

fn connector(base: &str, now: i64) -> Scim {
    let wire = Keyed::new("https://directory.acme.example", base, Present::Bearer { field: "token".into() }, Box::new(Vault), now).unwrap();
    Scim::new(Settings::new().with("group", "g-finance").unwrap(), Box::new(wire))
}

#[tokio::test]
async fn the_directory_is_read_rehearsed_changed_reconciled_and_undone() {
    let now = 1_667_293_200;
    let (base, calls, members) = directory().await;
    let service = connector(&base, now);
    let ticket = permission("credential-scim", "https://directory.acme.example", now);

    let found = service.discover(&ticket, now).await.unwrap();
    assert_eq!((found.reached[0].kind.as_str(), found.reached[0].id.as_str()), ("group", "g-finance"));
    assert!(found.note.contains("Finance desks") && found.note.contains("0 members"));

    let plan = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    assert_eq!(plan.steps().len(), 4);
    assert!(plan.alters(), "this one does change a directory, which is why it is behind the checked gate");
    assert!(service.alters_anything());

    // A rehearsal says what would happen and leaves the directory as it found it.
    let rehearsal = service.dry_run(&ticket, &plan, now).await.unwrap();
    assert_eq!(rehearsal.would_change().len(), 1);
    assert!(rehearsal.note.contains("would add them to") && rehearsal.note.contains("Nothing was changed"), "{}", rehearsal.note);
    assert!(members.lock().unwrap().is_empty(), "a dry run adds nobody");
    assert_eq!(service.observe(&ticket, &plan, now).await.unwrap().holds, Some(false));

    let checked = service.validate(&ticket, &plan, now).await.unwrap();
    let applied = service.apply(&ticket, &plan, &checked, now).await.unwrap();
    assert!(applied.changed && !applied.already);
    assert_eq!(members.lock().unwrap().iter().cloned().collect::<Vec<_>>(), vec!["u-ada".to_owned()]);
    assert_eq!(service.observe(&ticket, &plan, now).await.unwrap().holds, Some(true));

    // Reconciling is doing the same thing again, and it has to be free. Against this server, which
    // answers an add for an existing member with a 204 rather than a conflict, the only thing that
    // makes it free is that the connector reads the group first and sends nothing.
    calls.lock().unwrap().clear();
    let again = service.reconcile(&ticket, &plan, &checked, now + 1).await.unwrap();
    let once_more = service.reconcile(&ticket, &plan, &checked, now + 2).await.unwrap();
    assert!(again.already && !again.changed, "{}", again.note);
    assert_eq!(again.note, once_more.note, "reconciling twice says the same thing twice");
    assert_eq!(members.lock().unwrap().len(), 1, "and adds nobody twice");
    let patches = calls.lock().unwrap().iter().filter(|call| call.method == "PATCH").count();
    assert_eq!(patches, 0, "nothing was sent at all, which is what makes this safe at a directory that counts its writes");

    // Every change can be undone, and undoing it twice is free as well.
    let taken_back = service.revoke(&ticket, &plan, &checked, now + 3).await.unwrap();
    assert!(taken_back.changed && members.lock().unwrap().is_empty());
    assert!(service.revoke(&ticket, &plan, &checked, now + 4).await.unwrap().already);

    // The patches were the ones RFC 7644 section 3.5.2 describes.
    let calls = calls.lock().unwrap().clone();
    let patches: Vec<&Call> = calls.iter().filter(|call| call.method == "PATCH").collect();
    assert_eq!(patches.len(), 1, "one revoke changed the group, and the second found nothing to do");
    assert_eq!(patches[0].path, "/Groups/g-finance", "a patch goes to the group, never to the person");
    assert!(calls.iter().filter(|call| call.method == "GET").all(|call| call.path.starts_with("/Users?") || call.path == "/Groups/g-finance"), "{calls:?}");
    let body: serde_json::Value = serde_json::from_str(&patches[0].body).unwrap();
    assert_eq!(body["schemas"][0], PATCH_OP);
    assert_eq!(body["Operations"][0]["op"], "remove");
    assert_eq!(body["Operations"][0]["path"], "members[value eq \"u-ada\"]");
    assert!(calls.iter().all(|call| call.authorization == "Bearer a-directory-token"));

    // The history says which version of the credential authorised what, and never the value.
    let notes = service.export_audit();
    assert!(notes.iter().any(|note| note.reason.contains("credential version 3")), "{notes:?}");
    assert!(notes.iter().all(|note| !note.reason.contains("a-directory-token")));
}

/// PROVES that a group read without its members is a group whose members were not said, never a
/// group with none.
///
/// The connector read a missing `members` as an empty list. Against a directory that does not list
/// members when a group is read, a take-back then found the person "already out", sent nothing,
/// and reported the removal done while they kept the group: a removal that said it happened and
/// did not, which is invisible until somebody audits access. Now the connector says it cannot
/// tell, sends the change, and believes the directory's answer to that instead.
#[tokio::test]
async fn a_group_read_without_its_members_is_never_taken_for_an_empty_one() {
    let now = 1_667_293_200;
    let (base, calls, members) = directory_that(false).await;
    members.lock().unwrap().insert("u-ada".to_owned());
    let service = connector(&base, now);
    let ticket = permission("credential-scim", "https://directory.acme.example", now);

    let found = service.discover(&ticket, now).await.unwrap();
    assert!(!found.note.contains("0 members"), "a group whose members were not listed is not said to have none: {}", found.note);

    let plan = service.plan(&ticket, &Request::new(Change::TakeBack, ada()), now).unwrap();
    let seen = service.observe(&ticket, &plan, now).await.unwrap();
    assert_eq!(seen.holds, None, "nobody can tell from this answer whether Ada is out: {}", seen.note);
    let rehearsal = service.dry_run(&ticket, &plan, now).await.unwrap();
    assert!(!rehearsal.note.contains("already"), "a rehearsal does not claim what it could not read: {}", rehearsal.note);
    assert_eq!(members.lock().unwrap().len(), 1, "a dry run removes nobody");

    // Ada is in the group. The take-back is sent and she is really out.
    let checked = service.validate(&ticket, &plan, now).await.unwrap();
    let taken = service.apply(&ticket, &plan, &checked, now).await.unwrap();
    assert!(taken.changed && !taken.already, "{}", taken.note);
    assert!(members.lock().unwrap().is_empty(), "she no longer has the group");

    // Again: this server answers a removal that matches nobody with noTarget, which says she is out.
    let again = service.reconcile(&ticket, &plan, &checked, now + 1).await.unwrap();
    assert!(again.already && !again.changed, "{}", again.note);

    // Undoing the take-back gives the group back.
    let undone = service.revoke(&ticket, &plan, &checked, now + 2).await.unwrap();
    assert!(undone.changed, "{}", undone.note);
    assert!(members.lock().unwrap().contains("u-ada"));
    let patches = calls.lock().unwrap().iter().filter(|call| call.method == "PATCH").count();
    assert_eq!(patches, 3, "every change was sent, because none could be ruled out by reading");
}

#[tokio::test]
async fn nothing_changes_the_directory_until_that_exact_plan_has_been_checked() {
    let now = 1_667_293_200;
    let (base, _, members) = directory().await;
    let service = connector(&base, now);
    let ticket = permission("credential-scim", "https://directory.acme.example", now);
    let giving = service.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap();
    let taking_back = service.plan(&ticket, &Request::new(Change::TakeBack, ada()), now).unwrap();
    let checked = service.validate(&ticket, &giving, now).await.unwrap();

    // A proof covers one plan, however alike two of them look.
    let wrong = service.apply(&ticket, &taking_back, &checked, now).await.unwrap_err();
    assert!(matches!(wrong, Trouble::NotAllowed(_)) && wrong.say().contains("not the plan that was checked"));
    // And it goes stale.
    let stale = service.apply(&ticket, &giving, &checked, now + CHECKED_FOR).await.unwrap_err();
    assert!(stale.say().contains("checked too long ago"));
    assert!(service.reconcile(&ticket, &giving, &checked, now + CHECKED_FOR).await.is_err());
    assert!(service.revoke(&ticket, &giving, &checked, now + CHECKED_FOR).await.is_err());
    assert!(members.lock().unwrap().is_empty(), "nothing moved while the plan was refused");

    assert!(service.apply(&ticket, &giving, &checked, now + CHECKED_FOR - 1).await.is_ok());
    assert_eq!(members.lock().unwrap().len(), 1);
}

#[tokio::test]
async fn a_directory_that_cannot_name_one_person_is_told_so_rather_than_guessed_at() {
    let now = 1_667_293_200;
    let (base, _, members) = directory().await;
    let service = connector(&base, now);
    let ticket = permission("credential-scim", "https://directory.acme.example", now);

    // Nobody by that name: a missing, not a refusal, because nothing was wrong with the request.
    let stranger = Subject::new("nobody@acme.example", "Nobody").unwrap();
    let plan = service.plan(&ticket, &Request::new(Change::Give, stranger), now).unwrap();
    let missing = service.validate(&ticket, &plan, now).await.unwrap_err();
    assert!(matches!(missing, Trouble::Missing(_)) && missing.say().contains("is not in this directory"), "{}", missing.say());

    // Two accounts with the same address: this grid will not guess which was meant.
    let twins = Subject::new("twins@acme.example", "Twins").unwrap();
    let plan = service.plan(&ticket, &Request::new(Change::Give, twins), now).unwrap();
    let ambiguous = service.validate(&ticket, &plan, now).await.unwrap_err();
    assert!(ambiguous.say().contains("more than one account") && ambiguous.say().contains("will not guess"), "{}", ambiguous.say());
    assert!(members.lock().unwrap().is_empty());

    // A filter is a little language with quoted strings in it, so an address with a quote in it
    // would end the string early and the rest would be read as more filter. It is refused rather
    // than escaped, because an address with a quote in it is not an address anybody has.
    let awkward = Subject::new("a\"b@acme.example", "Awkward").unwrap();
    let refused = service.plan(&ticket, &Request::new(Change::Give, awkward), now).unwrap_err();
    assert!(matches!(refused, Trouble::Missing(_)) && refused.say().contains("quote"), "{}", refused.say());
    assert!(in_a_filter("ada@acme.example").is_ok());
    assert!(in_a_filter("a\\b@acme.example").is_err());

    // A connection that was not told which group says which setting is missing.
    let wire = Keyed::new("https://directory.acme.example", &base, Present::Bearer { field: "token".into() }, Box::new(Vault), now).unwrap();
    let bare = Scim::new(Settings::new(), Box::new(wire));
    let missing = bare.plan(&ticket, &Request::new(Change::Give, ada()), now).unwrap_err();
    assert!(matches!(missing, Trouble::Missing(_)) && missing.say().contains("group"), "{}", missing.say());
}

/// PROVES that a search answer this grid could not read is never taken for "nobody there".
///
/// The person was looked up with `Resources` read through `unwrap_or_default`, so a 2xx that was
/// not a list of people, such as a proxy's page or a broken body, became "is not in this directory,
/// so there is nobody to change". A take-back then told an admin there was nobody to take back
/// from while the person kept their account. RFC 7644 lets `Resources` be left out only when
/// `totalResults` is 0, and that answer is still believed.
#[tokio::test]
async fn a_search_answer_that_cannot_be_read_is_never_taken_for_nobody() {
    let now = 1_667_293_200;
    let (base, calls, members) = directory().await;
    let service = connector(&base, now);
    let ticket = permission("credential-scim", "https://directory.acme.example", now);
    for (address, what) in [("garbled@acme.example", "no list and no count"), ("hollow@acme.example", "an empty list that counts somebody")] {
        let person = Subject::new(address, "Somebody").unwrap();
        let plan = service.plan(&ticket, &Request::new(Change::TakeBack, person), now).unwrap();
        let unread = service.validate(&ticket, &plan, now).await.unwrap_err();
        assert!(!matches!(unread, Trouble::Missing(_)), "{what} was taken for nobody: {}", unread.say());
        assert!(unread.say().contains("could not be read") && !unread.say().contains("not in this directory"), "{what}: {}", unread.say());
    }
    // Nobody found, said the way the standard allows: still nobody.
    let quiet = Subject::new("quiet@acme.example", "Quiet").unwrap();
    let plan = service.plan(&ticket, &Request::new(Change::TakeBack, quiet), now).unwrap();
    let missing = service.validate(&ticket, &plan, now).await.unwrap_err();
    assert!(matches!(missing, Trouble::Missing(_)) && missing.say().contains("is not in this directory"), "{}", missing.say());
    assert!(members.lock().unwrap().is_empty());
    assert!(calls.lock().unwrap().iter().all(|call| call.method == "GET"), "nothing was changed on an answer that could not be read");
}

#[tokio::test]
async fn a_directory_that_says_no_leaves_this_grid_saying_so_in_its_own_words() {
    let now = 1_667_293_200;
    let (base, _, _) = directory().await;
    struct Wrong;
    impl Keys for Wrong {
        fn open(&self, _: &str) -> Result<Opened, String> {
            Ok(Opened { fields: json!({"token": "not the token"}), version: 1 })
        }
    }
    let wire = Keyed::new("https://directory.acme.example", &base, Present::Bearer { field: "token".into() }, Box::new(Wrong), now).unwrap();
    let service = Scim::new(Settings::new().with("group", "g-finance").unwrap(), Box::new(wire));
    let ticket = permission("credential-scim", "https://directory.acme.example", now);

    let refused = service.discover(&ticket, now).await.unwrap_err();
    assert!(matches!(refused, Trouble::Refused(_)) && refused.say().contains("401"), "{}", refused.say());
    // Nothing a directory said can carry a value into the history, because the connector puts the
    // status and a short piece of what came back into a note and nothing else.
    assert!(service.export_audit().iter().all(|note| !note.reason.contains("not the token")));

    // A plan this connector did not make is refused rather than carried out.
    let someone_elses = super::super::Plan::new("Azure Virtual Desktop", &ticket, Change::Give, ada(), "group g-finance", vec![super::super::Step::altering("x")]).unwrap();
    let checked = Checked::passed(&someone_elses, now);
    let refused = service.apply(&ticket, &someone_elses, &checked, now).await.unwrap_err();
    assert!(refused.say().contains("This plan is for Azure Virtual Desktop"), "{}", refused.say());
}

#[test]
fn the_row_says_what_this_really_is() {
    let row = super::super::registry::find(ROW).expect("SCIM 2.0 has a row in the registry");
    assert_eq!(row.state, super::super::registry::State::MockTested);
    assert!(row.evidence.contains("loopback"), "a mock-tested row names the server it was exercised against");
    assert!(row.evidence.contains("client"), "only the client direction is built, and the row says so");
    assert_eq!(PATCH_OP, "urn:ietf:params:scim:api:messages:2.0:PatchOp");
}
