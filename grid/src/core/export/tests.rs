//! What a sink sends, asserted on a computer with no network.
//!
//! The two sinks that are built are exercised twice over: once on the bytes `render` produces,
//! against a message written out by hand here from the specification, and once against a server on
//! this computer that reads the bytes back apart into fields. The second half is what makes the
//! claim "mock-tested" rather than "rendered": a frame whose octet count is wrong parses as
//! nothing, and a body whose integers are numbers rather than strings is a body a collector would
//! reject.
//!
//! The four that are interface only are exercised on their bytes alone, and the test says in terms
//! what that does not prove.
use super::*;
use crate::core::audit::{Entry, Event};
use crate::core::capability::{Authority, Claims};
use crate::core::connector::Ticket;
use crate::core::identity::{PrincipalKind, Role};
use crate::core::realm::{Capability, RealmKind};
use crate::core::Core;
use std::sync::{Arc, Mutex};

fn key() -> String {
    "c".repeat(64)
}

fn permission(destination: &str, now: i64) -> Ticket {
    let claims = Claims::new("realm-1", Capability::Credentials, "principal-ada", "device-ada", "work-1", "credential-1", now, 3_600).bound_to(destination, "POST", "/", 1 << 20);
    Ticket::read(&Authority::new("realm-1", &key()).mint(&claims).unwrap(), now).unwrap()
}

/// Two events, sealed as a realm seals them, so what is rendered is a real chain and not a struct
/// somebody filled in.
fn chain(at: i64) -> Vec<Event> {
    let allowed = Entry::new("realm-1", "principal-ada", "credential.lent", Decision::Allowed)
        .about(Capability::Credentials, "credential-1")
        .from("device-ada")
        .for_work("work-1")
        .because("POST /v1/charge at https://api.example")
        .under(3);
    let refused = Entry::new("realm-1", "principal-ada", "credential.refused", Decision::Refused).because("nobody has agreed to this use").under(3).under_command("pay-once");
    let first = Event::sealed(allowed, 41, at, "root".into(), &key());
    let second = Event::sealed(refused, 42, at + 1, first.seal.clone(), &key());
    vec![first, second]
}

/// A collector on loopback that keeps every byte it was given.
///
/// Deliberately not a parser: what it records is the bytes, and the test does the reading back, so
/// a mistake in this fixture cannot quietly make a test pass.
pub(crate) async fn collector() -> (String, Arc<Mutex<Vec<u8>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let kept: Arc<Mutex<Vec<u8>>> = Arc::default();
    let recorder = kept.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else { break };
            let recorder = recorder.clone();
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buffer = vec![0u8; 64 * 1024];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 {
                        break;
                    }
                    recorder.lock().unwrap().extend_from_slice(&buffer[..read]);
                }
            });
        }
    });
    (format!("127.0.0.1:{}", address.port()), kept)
}

/// An OTLP collector on loopback: answers the way the specification says and keeps the body.
async fn otlp_collector(reply: serde_json::Value, status: u16) -> (String, Arc<Mutex<Vec<(String, String)>>>) {
    use http_body_util::{BodyExt, Full};
    use hyper::{body::Incoming, Request, Response};
    use hyper_util::rt::TokioIo;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let seen: Arc<Mutex<Vec<(String, String)>>> = Arc::default();
    let recorder = seen.clone();
    let reply = Arc::new(reply);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else { break };
            let (recorder, reply) = (recorder.clone(), reply.clone());
            tokio::spawn(async move {
                let service = hyper::service::service_fn(move |request: Request<Incoming>| {
                    let (recorder, reply) = (recorder.clone(), reply.clone());
                    async move {
                        let path = request.uri().path().to_owned();
                        let bytes = request.into_body().collect().await.unwrap().to_bytes();
                        recorder.lock().unwrap().push((path, String::from_utf8_lossy(&bytes).into_owned()));
                        Ok::<_, std::convert::Infallible>(Response::builder().status(status).header("content-type", "application/json").body(Full::new(bytes::Bytes::from(reply.to_string()))).unwrap())
                    }
                });
                let _ = hyper::server::conn::http1::Builder::new().serve_connection(TokioIo::new(socket), service).await;
            });
        }
    });
    (format!("http://127.0.0.1:{}", address.port()), seen)
}

#[test]
fn a_syslog_frame_is_the_bytes_the_rfc_describes() {
    let at = 1_667_293_200;
    let events = chain(at);
    let sink = Syslog::new("127.0.0.1:6514", "hub-01", "realm-1").unwrap();

    // The message, written out here from RFC 5424 section 6, field by field.
    let message = sink.message(&events[0]);
    let expected = format!(
        "<110>1 2022-11-01T09:00:00Z hub-01 yougori-grid principal-ada credential.lent [yougori@0 seq=\"41\" realm=\"realm-1\" seal=\"{}\" previous=\"root\" policy=\"3\" decision=\"allowed\" device=\"device-ada\" work=\"work-1\"] POST /v1/charge at https://api.example",
        events[0].seal
    );
    assert_eq!(message, expected);
    // 13 * 8 + 6: log audit, informational. A refusal is a warning and not an error, because a
    // grid refusing something is the grid working.
    assert_eq!(110, u16::from(Syslog::AUDIT_FACILITY) * 8 + 6);
    assert!(sink.message(&events[1]).starts_with("<108>1 "), "{}", sink.message(&events[1]));

    // The frame: RFC 6587 octet counting, where the count is the byte length of the message.
    let rendered = sink.render(&events).unwrap();
    let text = String::from_utf8(rendered.clone()).unwrap();
    assert!(text.starts_with(&format!("{} <110>1 ", message.len())));

    // Read back apart, the way a collector reads it: take the count, take that many bytes, and
    // what is left is the next frame. A count that is wrong leaves nothing that parses.
    let mut rest = text.as_str();
    let mut read = Vec::new();
    while !rest.is_empty() {
        let (count, tail) = rest.split_once(' ').expect("a frame is a count, a space and that many bytes");
        let count: usize = count.parse().expect("the count is a number");
        read.push(tail[..count].to_owned());
        rest = &tail[count..];
    }
    assert_eq!(read.len(), 2);
    assert_eq!(read[0], message);
    assert!(read[1].contains("seq=\"42\"") && read[1].contains("decision=\"refused\""));

    // The placeholder is named as one, because a collector that checks enterprise numbers will
    // reject or mis-attribute every message until a customer replaces it.
    assert_eq!(PLACEHOLDER_ENTERPRISE_NUMBER, 0);
    assert!(message.contains("[yougori@0 "));
}

#[test]
fn nothing_a_syslog_message_carries_can_break_the_frame_or_the_fields() {
    let at = 1_667_293_200;
    let mut events = chain(at);
    // A reason with the three characters that end a structured data parameter early, a newline
    // that would split a message at a collector framing on newlines, and a principal with a space
    // in it, which a header field cannot have.
    events[0].reason = "they said \"no\\thing]\" and\nthen left".into();
    events[0].principal_id = "an id with spaces".into();
    let sink = Syslog::new("127.0.0.1:6514", "hub 01 with spaces", "realm]1").unwrap();
    let message = sink.message(&events[0]);

    assert!(message.contains("realm=\"realm\\]1\""), "a bracket in a parameter is escaped: {message}");
    assert!(!message.contains('\n'), "a newline in a reason would be the end of a message: {message}");
    assert!(message.contains(" hub01withspaces "), "a header field is printable ASCII with no spaces: {message}");
    assert!(message.contains(" anidwithspaces "), "{message}");
    // The frame still reads back, which is the thing all of that protects.
    let rendered = String::from_utf8(sink.render(&events[..1]).unwrap()).unwrap();
    let (count, tail) = rendered.split_once(' ').unwrap();
    assert_eq!(tail.len(), count.parse::<usize>().unwrap());

    // An event with nothing to say still says something, because a message with an empty body is
    // a message a collector files as empty.
    let mut silent = events[1].clone();
    silent.reason = String::new();
    assert!(sink.message(&silent).ends_with(" credential.refused"), "{}", sink.message(&silent));
    assert!(Syslog::new("", "hub", "realm-1").is_err() && Syslog::new("a collector with spaces:514", "hub", "realm-1").is_err());
}

#[tokio::test]
async fn a_syslog_collector_on_this_computer_receives_exactly_what_was_rendered() {
    let at = 1_667_293_200;
    let events = chain(at);
    let (address, kept) = collector().await;
    let sink = Syslog::new(&address, "hub-01", "realm-1").unwrap();
    let ticket = permission("https://collector.example", at);

    let reached = sink.deliver(&ticket, &events, at).await.unwrap();
    assert_eq!(reached, 42, "a sink answers with the highest sequence the far end took");
    // Give the collector's own task a moment to drain the socket before reading what it kept.
    for _ in 0..50 {
        if !kept.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(*kept.lock().unwrap(), sink.render(&events).unwrap(), "what went down the socket is what render said it would be");

    // Nothing is sent anywhere but this computer. A collector elsewhere would mean a sealed
    // history over a plain connection, and this refuses rather than doing it.
    let elsewhere = Syslog::new("collector.acme.example:6514", "hub-01", "realm-1").unwrap();
    let refused = elsewhere.deliver(&ticket, &events, at).await.unwrap_err();
    assert!(refused.say().contains("only to a collector on this computer"), "{}", refused.say());

    // An expired permission sends nothing, and an empty batch confirms nothing.
    assert!(sink.deliver(&ticket, &events, ticket.expires_at()).await.is_err());
    assert_eq!(sink.deliver(&ticket, &[], at).await.unwrap(), 0);
}

#[test]
fn an_otlp_body_is_the_json_mapping_the_specification_describes() {
    let at = 1_667_293_200;
    let events = chain(at);
    let sink = Otlp::new("http://127.0.0.1:4318", "realm-1").unwrap();
    let body = sink.body(&events);

    let resource = &body["resourceLogs"][0]["resource"]["attributes"];
    assert_eq!(resource[0], serde_json::json!({"key": "service.name", "value": {"stringValue": "yougori-grid"}}));
    assert_eq!(resource[1], serde_json::json!({"key": "service.instance.id", "value": {"stringValue": "realm-1"}}));

    let records = &body["resourceLogs"][0]["scopeLogs"][0]["logRecords"];
    assert_eq!(records.as_array().unwrap().len(), 2);
    // Proto3 JSON encodes a 64-bit integer as a string. A collector reading a number here loses
    // precision or rejects the record, and this is exactly the detail a renderer gets wrong.
    assert_eq!(records[0]["timeUnixNano"], serde_json::json!("1667293200000000000"));
    assert!(records[0]["timeUnixNano"].is_string(), "not a number: proto3 JSON says a 64-bit integer is a string");
    assert_eq!(records[0]["observedTimeUnixNano"], records[0]["timeUnixNano"]);
    assert_eq!((records[0]["severityNumber"].as_i64(), records[0]["severityText"].as_str()), (Some(9), Some("INFO")));
    assert_eq!((records[1]["severityNumber"].as_i64(), records[1]["severityText"].as_str()), (Some(13), Some("WARN")));
    assert_eq!(records[0]["body"]["stringValue"], "POST /v1/charge at https://api.example");

    let attributes: Vec<(String, String)> = records[0]["attributes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|attribute| (attribute["key"].as_str().unwrap().to_owned(), attribute["value"]["stringValue"].as_str().unwrap().to_owned()))
        .collect();
    assert!(attributes.contains(&("yougori.sequence".into(), "41".into())), "{attributes:?}");
    assert!(attributes.contains(&("yougori.seal".into(), events[0].seal.clone())));
    assert!(attributes.contains(&("yougori.previous_seal".into(), "root".into())));
    assert!(attributes.contains(&("yougori.policy_version".into(), "3".into())));
    assert!(attributes.contains(&("yougori.decision".into(), "allowed".into())));
    assert!(attributes.contains(&("enduser.id".into(), "principal-ada".into())));
    assert!(attributes.contains(&("device.id".into(), "device-ada".into())));
    // A field the event does not have is not an attribute with an empty value.
    assert!(!attributes.iter().any(|(key, _)| key == "yougori.command"));
    let second: Vec<String> = records[1]["attributes"].as_array().unwrap().iter().map(|attribute| attribute["key"].as_str().unwrap().to_owned()).collect();
    assert!(second.contains(&"yougori.command".to_owned()) && !second.contains(&"device.id".to_owned()));

    assert_eq!(sink.render(&events).unwrap(), body.to_string().into_bytes());
    assert_eq!(Otlp::PATH, "/v1/logs");
}

#[tokio::test]
async fn an_otlp_collector_takes_the_body_and_a_partial_success_marks_nothing() {
    let at = 1_667_293_200;
    let events = chain(at);
    let ticket = permission("https://collector.example", at);

    let (base, seen) = otlp_collector(serde_json::json!({}), 200).await;
    let sink = Otlp::new(&base, "realm-1").unwrap();
    assert_eq!(sink.deliver(&ticket, &events, at).await.unwrap(), 42);
    let calls = seen.lock().unwrap().clone();
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].0, "/v1/logs");
    assert_eq!(calls[0].1, String::from_utf8(sink.render(&events).unwrap()).unwrap());

    // A collector that kept part of the batch names how many it dropped and not which, so there
    // is no sequence number to mark and nothing is marked.
    let (base, _) = otlp_collector(serde_json::json!({"partialSuccess": {"rejectedLogRecords": "1", "errorMessage": "one was malformed"}}), 200).await;
    let partial = Otlp::new(&base, "realm-1").unwrap();
    let refused = partial.deliver(&ticket, &events, at).await.unwrap_err();
    assert!(refused.say().contains("dropped 1 records") && refused.say().contains("Nothing has been marked exported"), "{}", refused.say());

    // The same answer with the count written as a number. proto3 JSON writes a 64-bit integer as
    // a string, but a parser has to take a number and collectors send one, and reading that as
    // nothing dropped would mark the whole batch exported and let the trim throw away the records
    // the collector had just refused.
    let (base, _) = otlp_collector(serde_json::json!({"partialSuccess": {"rejectedLogRecords": 7, "errorMessage": "seven were malformed"}}), 200).await;
    let refused = Otlp::new(&base, "realm-1").unwrap().deliver(&ticket, &events, at).await.unwrap_err();
    assert!(refused.say().contains("dropped 7 records"), "{}", refused.say());

    // And a count in no shape this grid can read is a refusal too, not a silent nought.
    let (base, _) = otlp_collector(serde_json::json!({"partialSuccess": {"rejectedLogRecords": {"count": 7}}}), 200).await;
    let refused = Otlp::new(&base, "realm-1").unwrap().deliver(&ticket, &events, at).await.unwrap_err();
    assert!(refused.say().contains("could not read"), "{}", refused.say());

    // And a collector that said no said no.
    let (base, _) = otlp_collector(serde_json::json!({"message": "unauthorised"}), 401).await;
    let refused = Otlp::new(&base, "realm-1").unwrap().deliver(&ticket, &events, at).await.unwrap_err();
    assert!(refused.say().contains("did not take this batch"), "{}", refused.say());
}

#[tokio::test]
async fn a_vendor_envelope_is_rendered_and_never_claimed_to_have_been_accepted() {
    let at = 1_667_293_200;
    let events = chain(at);
    let ticket = permission("https://siem.example", at);

    // Splunk: concatenated JSON objects with no separator at all, which is the detail people get
    // wrong by putting commas between them.
    let splunk = Vendor::new(Envelope::SplunkHec, "https://splunk.acme.example:8088", "realm-1", "yougori-audit").unwrap();
    let body = String::from_utf8(splunk.render(&events).unwrap()).unwrap();
    assert!(body.starts_with(&format!("{{\"event\":")) || body.contains("\"sourcetype\":\"_json\""), "{body}");
    assert!(!body.contains("},{"), "Splunk takes objects back to back and not an array: {body}");
    assert_eq!(body.matches("\"time\":").count(), 2);
    assert!(body.contains("\"index\":\"yougori-audit\""));
    assert_eq!(Envelope::SplunkHec.path(), "/services/collector/event");

    // Elastic: alternating action and document lines, and the trailing newline the bulk API needs
    // and that people forget.
    let elastic = Vendor::new(Envelope::Elastic, "https://elastic.acme.example:9200", "realm-1", "yougori-audit").unwrap();
    let body = String::from_utf8(elastic.render(&events).unwrap()).unwrap();
    let lines: Vec<&str> = body.split('\n').collect();
    assert_eq!(lines.len(), 5, "two documents is four lines and the empty one after the final newline: {lines:?}");
    assert_eq!(lines[4], "", "the bulk API rejects a body whose last line has no newline after it");
    assert_eq!(serde_json::from_str::<serde_json::Value>(lines[0]).unwrap(), serde_json::json!({"create": {"_index": "yougori-audit"}}));
    assert_eq!(serde_json::from_str::<serde_json::Value>(lines[1]).unwrap()["sequence"], 41);
    assert_eq!(String::from_utf8(elastic.render(&[]).unwrap()).unwrap(), "\n");

    // A generic webhook: newline-delimited JSON, one event a line.
    let webhook = Vendor::new(Envelope::Webhook, "https://siem.acme.example", "realm-1", "yougori-audit").unwrap();
    let body = String::from_utf8(webhook.render(&events).unwrap()).unwrap();
    assert_eq!(body.lines().count(), 2);
    assert_eq!(serde_json::from_str::<serde_json::Value>(body.lines().next().unwrap()).unwrap()["seal"], events[0].seal);

    // Sentinel: one array, with TimeGenerated in RFC 3339.
    let sentinel = Vendor::new(Envelope::Sentinel, "https://acme-abcd.westeurope-1.ingest.monitor.azure.com", "realm-1", "Custom-Yougori_CL").unwrap();
    let rows: serde_json::Value = serde_json::from_slice(&sentinel.render(&events).unwrap()).unwrap();
    assert_eq!(rows.as_array().unwrap().len(), 2);
    assert_eq!(rows[0]["TimeGenerated"], "2022-11-01T09:00:00Z");

    // And not one of them has ever sent anything. What this test proves is that the envelope is
    // the one the vendor documents. It does not prove the index exists, that a data collection
    // rule is bound to the stream, that a token has the right scope, or that the service would
    // take the batch at all, and none of those can be known from this repository.
    for sink in [&splunk, &elastic, &webhook, &sentinel] {
        let refused = sink.deliver(&ticket, &events, at).await.unwrap_err();
        assert!(refused.say().contains("has ever sent it"), "{}", refused.say());
        assert!(refused.say().contains("syslog") || refused.say().contains("OpenTelemetry"), "the refusal says what is built instead: {}", refused.say());
        assert!(!sink.name().is_empty() && !sink.destination().is_empty());
    }
    assert!(Vendor::new(Envelope::Webhook, "http://siem.acme.example", "realm-1", "x").is_err(), "a sealed history does not leave this computer in the clear");
}

/// A sink that confirms whatever it is told to, without reaching anything. For the two cases a
/// real collector cannot be made to produce on demand: one that says it took nothing, and one that
/// says it took part of a batch.
struct Says(u64);

impl Sink for Says {
    fn name(&self) -> &'static str {
        "Syslog over TCP to a collector on this computer"
    }
    fn destination(&self) -> &str {
        "127.0.0.1:1"
    }
    fn render(&self, _events: &[Event]) -> Result<Vec<u8>, String> {
        Ok(Vec::new())
    }
    fn deliver<'a>(&'a self, _ticket: &'a Ticket, events: &'a [Event], _now: i64) -> crate::core::connector::Answer<'a, u64> {
        let answer = if self.0 == 0 { 0 } else { events.first().map(|event| event.sequence).unwrap_or(0) + self.0 - 1 };
        Box::pin(async move { Ok(answer) })
    }
}

#[tokio::test]
async fn nothing_is_marked_exported_on_a_guess() {
    use crate::core::identity::{PrincipalKind, Role};
    use crate::core::realm::RealmKind;
    use crate::core::Core;
    let at = 1_667_293_200;
    let folder = tempfile::tempdir().unwrap();
    let path = folder.path().join("realm.db");
    let mut core = Core::create(&path, "Acme", RealmKind::Primary, &[Capability::Credentials], &key(), at).unwrap();
    let person = core.add_principal("owner", PrincipalKind::Person, "Ada", &[Role::Auditor], at).unwrap().id;
    let onlooker = core.add_principal("owner", PrincipalKind::Person, "Bob", &[Role::User], at).unwrap().id;
    for step in 0..4 {
        core.add_principal("owner", PrincipalKind::Person, &format!("Person {step}"), &[Role::User], at).unwrap();
    }
    let head = core.snapshot().unwrap().audit.events.last().unwrap().sequence;
    let ticket = permission("https://collector.example", at);
    assert_eq!(ticket.principal_id(), "principal-ada");

    // An export is a read of the whole sealed history, so it asks for the same permission every
    // other read of it asks for. The ticket is not that permission and cannot stand in for it:
    // `Ticket::read` checks no signature, so everything a ticket says about who is asking is text
    // whoever built it chose.
    let refused = core.export_history(&onlooker, &Says(2), &ticket, at).await.unwrap_err();
    assert!(refused.contains("may not read audit"), "{refused}");
    assert_eq!(core.since(0).unwrap().len() as u64, head, "a refused export marked nothing");

    // A sink that cannot tell which of a batch were accepted moves nothing, so the local chain
    // keeps every event and `Store::trim` will not drop any of it.
    assert_eq!(core.export_history(&person, &Says(0), &ticket, at).await.unwrap(), 0);
    assert_eq!(core.since(0).unwrap().len() as u64, head, "nothing was marked, so everything is still waiting");

    // A sink that accepted the first two of them moves the marker to exactly the second and no
    // further, and the next export carries only what is left. An export that confirmed something
    // writes an event of its own saying so, which is why there is one more waiting than the
    // arithmetic on its own would suggest.
    assert_eq!(core.export_history(&person, &Says(2), &ticket, at).await.unwrap(), 2);
    assert_eq!(core.since(2).unwrap().len() as u64, head - 2 + 1);

    // A real collector on this computer takes the rest, and the marker reaches the head as it was
    // at the moment the export started.
    let (address, kept) = collector().await;
    let sink = Syslog::new(&address, "hub-01", &core.realm().id).unwrap();
    let before = core.snapshot().unwrap().audit.events.last().unwrap().sequence;
    let reached = core.export_history(&person, &sink, &ticket, at).await.unwrap();
    assert_eq!(reached, before);
    for _ in 0..50 {
        if !kept.lock().unwrap().is_empty() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert!(!kept.lock().unwrap().is_empty());
    // What the history says about it never claims more than this grid knows.
    let said = core.snapshot().unwrap().audit.events.iter().find(|event| event.action == "audit.exported").map(|event| event.reason.clone()).unwrap();
    assert!(said.contains("knows they were sent and not that they were stored"), "{said}");
    // And the person the history names is the one this grid was acting for, never the name the
    // ticket carried, which nothing has checked.
    let who = core.snapshot().unwrap().audit.events.iter().find(|event| event.action == "audit.exported").map(|event| event.principal_id.clone()).unwrap();
    assert_eq!(who, person);
    assert_ne!(who, ticket.principal_id(), "the ticket names somebody else, and an unsigned ticket does not get to name anybody");

    // A far end claiming it took more than it was sent cannot make this grid drop events nobody
    // has a copy of. The marker stops at what the batch actually held, which here is the one
    // event the export above wrote.
    let waiting = core.since(reached).unwrap();
    assert_eq!(waiting.len(), 1);
    assert_eq!(core.export_history(&person, &Says(1_000), &ticket, at).await.unwrap(), waiting[0].sequence);

    // A history somebody edited is never laundered into a customer's collector. The chain is
    // verified before anything is sent, and the export refuses rather than exporting a chain that
    // no longer verifies.
    core.close().unwrap();
    let connection = rusqlite::Connection::open(&path).unwrap();
    connection.execute_batch("DROP TRIGGER audit_events_never_change; UPDATE audit_events SET reason = 'rewritten' WHERE sequence = 3;").unwrap();
    drop(connection);
    let mut spoiled = Core::open(&path, &key()).unwrap();
    let refused = spoiled.export_history(&person, &sink, &ticket, at).await.unwrap_err();
    assert!(refused.contains("Event 3 was altered"), "{refused}");
}

#[test]
fn a_batch_is_bounded_and_a_sink_names_the_row_it_is() {
    assert_eq!(BATCH, 500);
    let syslog = Syslog::new("127.0.0.1:6514", "hub-01", "realm-1").unwrap();
    let otlp = Otlp::new("http://127.0.0.1:4318", "realm-1").unwrap();
    // Every sink names a row in the registry, so a sink cannot claim more than the matrix does.
    for name in [syslog.name(), otlp.name(), Envelope::Webhook.row(), Envelope::SplunkHec.row(), Envelope::Elastic.row(), Envelope::Sentinel.row()] {
        assert!(crate::core::connector::registry::find(name).is_some(), "{name} has no row in the registry");
    }
    assert_eq!(APPLICATION, "yougori-grid");
}

/// PROVES that a realm that can reach nothing can still stop its history growing for ever, and
/// that it does so without the rule being weakened anywhere: an unexported event is still never
/// dropped, writing a bundle marks nothing at all, and the marker moves only against the bundle
/// an operator actually carried away.
///
/// The realm this is about is the research one. It is built to reach nothing, so it can never
/// export, so the marker never moves, so `Store::trim` never drops anything and the chain grows
/// for as long as the realm runs. The answer is not a looser trim; it is giving the operator the
/// bytes and then taking their word for it, once, against the file.
///
/// Six things are checked, and five of them are refusals: a bundle from another realm, a bundle
/// somebody edited, a bundle whose last event is not the event this realm holds at that number,
/// a bundle handed back twice, and a file that is not a bundle at all.
///
/// DOES NOT PROVE that the operator really carried the file anywhere. Nothing can prove that from
/// here, which is exactly why writing the bundle marks nothing and why confirming it is a
/// separate act by a named person that the realm records.
#[test]
fn a_realm_that_can_reach_nothing_can_still_get_its_history_off_this_computer() {
    let folder = tempfile::tempdir().unwrap();
    let now = 900_000;
    let mut core = Core::create(&folder.path().join("research.db"), "Acme Research", RealmKind::Research, &[Capability::Research], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::SecurityAdmin], now).unwrap();
    for step in 0..5 {
        core.enrol_device(&admin.id, &format!("Bench {step}"), "linux", now + step).unwrap();
    }
    let before = core.reading(now).unwrap();
    assert!(before.audit_events_never_exported >= 6, "a realm that has never exported holds everything it wrote");

    // Writing the bundle marks nothing. This is the half that must not be got wrong: a file on
    // the same disk as the realm is not a copy of anything.
    let carried = folder.path().join("carry").join(format!("acme.{BUNDLE}"));
    let bundle = core.write_history_out(&admin.id, &carried, now + 10).unwrap();
    assert_eq!(bundle.realm_id, core.realm().id);
    assert_eq!(bundle.after, 0);
    assert_eq!(bundle.len(), before.audit_events_never_exported);
    assert_eq!(core.reading(now + 10).unwrap().audit_events_never_exported, bundle.len() + 1, "writing it marked nothing, and recording that it was written is itself one more event");
    assert!(carried.exists());
    assert!(core.history().is_ok());

    // A bundle another realm wrote does not move this one's marker, whatever it says inside.
    let other_folder = folder.path().join("other");
    let mut other = Core::create(&other_folder.join("other.db"), "Somebody Else", RealmKind::Primary, &[Capability::Models], &"b".repeat(64), now).unwrap();
    let their_admin = other.add_principal("owner", PrincipalKind::Person, "Hedy", &[Role::SecurityAdmin], now).unwrap();
    let theirs = other_folder.join(format!("theirs.{BUNDLE}"));
    other.write_history_out(&their_admin.id, &theirs, now + 11).unwrap();
    assert!(core.carried_out(&admin.id, &theirs, now + 12).unwrap_err().contains("written by another grid"));

    // A bundle somebody edited is refused by the seal, under this realm's own key, which is the
    // same check the realm holds its own chain to.
    let edited = folder.path().join(format!("edited.{BUNDLE}"));
    let mut spoiled = bundle.clone();
    spoiled.events[1].reason = "rewritten".into();
    std::fs::write(&edited, serde_json::to_vec(&spoiled).unwrap()).unwrap();
    let refused = core.carried_out(&admin.id, &edited, now + 13).unwrap_err();
    assert!(refused.contains("altered"), "{refused}");

    // A bundle that claims to reach past what this realm has written is refused rather than
    // moving the marker to a number nobody can check.
    let invented = folder.path().join(format!("invented.{BUNDLE}"));
    let mut ahead = bundle.clone();
    ahead.reaches = 10_000;
    std::fs::write(&invented, serde_json::to_vec(&ahead).unwrap()).unwrap();
    assert!(core.carried_out(&admin.id, &invented, now + 14).unwrap_err().contains("reaches further than its own last event"));

    // And a file that is not a bundle says so rather than being read as an empty one.
    let rubbish = folder.path().join("notes.txt");
    std::fs::write(&rubbish, b"this is not a history").unwrap();
    assert!(core.carried_out(&admin.id, &rubbish, now + 15).unwrap_err().contains("not a history bundle"));

    // Nothing above moved anything.
    assert_eq!(core.store_for_tests().exported_to().unwrap(), 0);

    // The operator carries the real one away and says so. Now, and only now, the marker moves.
    let reached = core.carried_out(&admin.id, &carried, now + 16).unwrap();
    assert_eq!(reached, bundle.reaches);
    assert_eq!(core.store_for_tests().exported_to().unwrap(), bundle.reaches);
    assert!(core.verify_audit().is_ok(), "and the realm's own history still verifies");
    let said = core.snapshot().unwrap().audit.events.iter().rev().find(|event| event.action == "audit.carried out").unwrap().reason.clone();
    assert!(said.contains("checked against the bundle that was carried"), "{said}");

    // Handing the same bundle back a second time changes nothing and says so.
    assert!(core.carried_out(&admin.id, &carried, now + 17).unwrap_err().contains("already carried its history out"));

    // The trim rule itself has not moved: what is now droppable is what was carried out, and the
    // events written since are not, which is what `Store::trim` is held to.
    let left = core.reading(now + 18).unwrap();
    assert!(left.audit_events_never_exported > 0 && left.audit_events_never_exported < bundle.len(), "{left:?}");
}

/// PROVES that the marker only ever moves over history that was actually carried out: a bundle
/// whose front is missing does not vouch for the events it skipped, and a number typed by hand
/// cannot reach past what this realm has written.
///
/// The marker is the one thing standing between an event and the delete guard letting it go, so
/// every way of moving it is a way of arranging for history to be dropped. A bundle holding
/// events 4 to 9 verifies on its own terms — its seals chain, its last event is the one this
/// realm holds — and used to carry the marker from nothing to nine, leaving one, two and three
/// marked as carried out when nobody had carried them anywhere. A typed number did the same more
/// directly, by naming a sequence this realm has never written.
#[test]
fn the_export_marker_never_passes_history_that_was_not_carried_out() {
    let folder = tempfile::tempdir().unwrap();
    let now = 910_000;
    let mut core = Core::create(&folder.path().join("research.db"), "Acme Research", RealmKind::Research, &[Capability::Research], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::SecurityAdmin], now).unwrap();
    for step in 0..8 {
        core.enrol_device(&admin.id, &format!("Bench {step}"), "linux", now + step).unwrap();
    }
    let whole = core.write_history_out(&admin.id, &folder.path().join(format!("whole.{BUNDLE}")), now + 10).unwrap();
    assert!(whole.len() > 4, "there is a front to cut off");

    // The same bundle with its front cut off. Its seals still chain, because they are this
    // realm's own seals, and its last event is still the event this realm holds. The only thing
    // wrong with it is what it does not hold.
    let cut = folder.path().join(format!("cut.{BUNDLE}"));
    let mut truncated = whole.clone();
    truncated.events.drain(..3);
    truncated.after = truncated.events[0].sequence - 1;
    std::fs::write(&cut, serde_json::to_vec(&truncated).unwrap()).unwrap();
    assert!(truncated.verify(&key()).is_ok(), "it is whole on its own terms, which is the point");

    let refused = core.carried_out(&admin.id, &cut, now + 11).unwrap_err();
    assert!(refused.contains("1"), "the refusal names the first event nobody has carried out: {refused}");
    assert_eq!(core.store_for_tests().exported_to().unwrap(), 0, "and the marker did not move over them");

    // A number typed by hand cannot reach past the end of the history either.
    let (head, _) = core.store_for_tests().head().unwrap();
    let refused = core.exported(&admin.id, head + 500, now + 12).unwrap_err();
    assert!(refused.contains("has not written"), "{refused}");
    assert_eq!(core.store_for_tests().exported_to().unwrap(), 0);

    // The whole bundle still works, and the marker moves exactly as far as it reaches.
    let reached = core.carried_out(&admin.id, &folder.path().join(format!("whole.{BUNDLE}")), now + 13).unwrap();
    assert_eq!(reached, whole.reaches);
    assert_eq!(core.store_for_tests().exported_to().unwrap(), whole.reaches);

    // And from there the next bundle joins on, which is the case the gap check must not break.
    core.enrol_device(&admin.id, "Bench later", "linux", now + 14).unwrap();
    let next = core.write_history_out(&admin.id, &folder.path().join(format!("next.{BUNDLE}")), now + 15).unwrap();
    assert_eq!(next.after, whole.reaches, "it starts where the last one stopped");
    assert_eq!(core.carried_out(&admin.id, &folder.path().join(format!("next.{BUNDLE}")), now + 16).unwrap(), next.reaches);
}

/// PROVES that writing a history bundle never writes over a file that is already there, and that
/// what the operator carries away is on the disk rather than still in this computer's hands.
///
/// The file used to be made by asking whether one was there and then writing. Between the
/// question and the answer somebody else's file can appear at that path, and the write destroys
/// it; the read-back afterwards is happy, because what comes back is what this realm just wrote.
/// Making the file in one call either makes it or says it is already there, with nothing in
/// between. The bundle is then put on the disk before it is called written, because it is the one
/// copy of events the realm may be allowed to drop afterwards.
///
/// DOES NOT PROVE that the race is gone, which no test here can observe; it proves the refusal
/// the race turned into, and that the file it refuses is left exactly as it was.
#[test]
fn a_history_bundle_is_never_written_over_a_file_that_is_already_there() {
    let folder = tempfile::tempdir().unwrap();
    let now = 920_000;
    let mut core = Core::create(&folder.path().join("research.db"), "Acme Research", RealmKind::Research, &[Capability::Research], &key(), now).unwrap();
    let admin = core.add_principal("owner", PrincipalKind::Person, "Grace", &[Role::SecurityAdmin], now).unwrap();
    core.enrol_device(&admin.id, "Bench", "linux", now + 1).unwrap();

    // Somebody's file is already at that path, and it is not a bundle.
    let taken = folder.path().join(format!("taken.{BUNDLE}"));
    std::fs::write(&taken, b"somebody else's file").unwrap();
    let refused = core.write_history_out(&admin.id, &taken, now + 2).unwrap_err();
    assert!(refused.contains("already a file"), "{refused}");
    assert_eq!(std::fs::read(&taken).unwrap(), b"somebody else's file", "and it is still theirs, byte for byte");

    // Somewhere free, into a folder that does not exist yet, it is written and reads back as the
    // bundle this realm wrote.
    let fresh = folder.path().join("carry").join(format!("fresh.{BUNDLE}"));
    let bundle = core.write_history_out(&admin.id, &fresh, now + 3).unwrap();
    let back = Bundle::read(&fresh).unwrap();
    assert_eq!(back.reaches, bundle.reaches);
    assert_eq!(back.events.len(), bundle.events.len());
    assert!(back.verify(&key()).is_ok());

    // And its own path is taken now, so writing again says so rather than replacing it.
    let twice = core.write_history_out(&admin.id, &fresh, now + 4).unwrap_err();
    assert!(twice.contains("already a file"), "{twice}");
    assert_eq!(std::fs::read(&fresh).unwrap(), serde_json::to_vec_pretty(&bundle).unwrap(), "the bundle on the disk is untouched");
}
