//! Where a realm's sealed history goes, so it survives whoever holds this computer.
//!
//! This is not a `Connector` and it could not be one. A connector's `Request` names a person by
//! their email and its `Plan` is about one person at one target; a batch of events is neither, and
//! `revoke` has no meaning for an event that has already been sent. Forcing a sink through that
//! shape would mean inventing a person for every batch, so there is a second seam here with the
//! two operations a stream of events actually needs.
//!
//! The first of those two is the one that matters for anything that can be proved here. `render`
//! produces exactly the bytes a sink would send, and sends nothing. That is why a wire format can
//! be checked on a computer with no network at all, and it is what the tests in this module assert
//! on. The second, `deliver`, is where the bytes go somewhere, and it is the half this repository
//! cannot prove anything about: there is no collector here, no SIEM and no vendor account.
//!
//! The distinction the documentation has to make is not "has a format" against "has none". Every
//! sink below has a documented format and every one of them can have its bytes asserted offline.
//! What differs is **acceptance**:
//!
//! - Syslog and OTLP over HTTP with JSON encoding are built and exercised against a server on this
//!   computer that speaks the published protocol and reads the message back apart into its fields.
//!   The framing of a syslog message is a byte count a test recomputes, and the OTLP mapping is a
//!   published specification a test asserts field by field.
//! - The SIEM webhook, Splunk HEC, Microsoft Sentinel and Elastic are interface only. Their
//!   envelopes are rendered here, from the vendors' published formats, and `deliver` refuses with
//!   a sentence saying why. Nothing in this repository has ever been pointed at one of them, and
//!   whether an index exists, whether a data collection rule is bound to a stream, whether a token
//!   has the right scope and whether the service rejects a batch for a reason that is not in the
//!   documentation are four things that cannot be known from here. Rendering an envelope is worth
//!   doing and it is not the same as having delivered one, so the state in the registry says
//!   interface only and this file says it in the refusal too.
//!
//! Marking events exported is what lets the local chain be trimmed: `Store::trim` drops events
//! only as far as `exported_to`, so a realm nobody ever carries anything out of keeps every event
//! it has written, for ever. `Core::export_history` moves that marker, and only as far as a sink
//! actually confirmed.
//!
//! ## The realm that can reach nothing
//!
//! Every sink above needs a network, and an authorised research realm may have none at all: it is
//! built to reach nothing, so it can never export, so the marker never moves, so nothing is ever
//! dropped and its chain grows for as long as it runs. That is a real way to fill a disk and it
//! was written down as a gap rather than solved.
//!
//! It is not solved by weakening the rule. An unexported event is still never dropped, and the
//! database still refuses to drop one. What an operator is given instead is a `Bundle`: every
//! event the realm has not yet got off this computer, written to a file they can carry away on a
//! disk, with the realm it came from and the span it covers named in it, and every seal in it
//! checked by reading the written file back before it is called written.
//!
//! The marker does not move when the bundle is written, and that is the part that matters. A
//! bundle on the same disk as the realm is not a copy of anything: one disk failure loses both.
//! So writing it moves nothing, and `Core::carried_out` is a second step the operator takes after
//! the bundle is somewhere else. That step is keyed on the bundle rather than on a number: it
//! reads the file the operator actually has, checks it belongs to this realm, checks every seal in
//! it under the realm's key, and checks that the last event in it is the event this realm has at
//! that sequence, with the same seal. Only then does the marker move, and only as far as the
//! bundle reaches. A number somebody typed will not move it, and neither will a bundle from
//! another realm, a bundle somebody edited, or a bundle that has been truncated.
use super::audit::{Chain, Decision, Event};
use super::connector::{Answer, Ticket, Trouble};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[cfg(test)]
mod tests;

/// How many events go in one batch. Five hundred, because a syslog collector reads one message at
/// a time and an OTLP collector reads one body, and five hundred events is a body of a size any
/// of them accepts without a fight.
pub const BATCH: usize = 500;

/// The enterprise number in the syslog structured data element.
///
/// Zero is a placeholder and not a registered IANA private enterprise number. A customer shipping
/// this needs their own, and the constant is named so that nobody reads it as a real one. A
/// collector that checks enterprise numbers will reject or mis-attribute every message until it is
/// replaced, and that is worth a build-time name rather than a line in a document.
pub const PLACEHOLDER_ENTERPRISE_NUMBER: u32 = 0;

/// What this product calls itself to a collector.
pub const APPLICATION: &str = "yougori-grid";

/// Where a realm's sealed history goes.
pub trait Sink: Send + Sync {
    /// Which row of `connector::registry::INTEGRATIONS` this is, so a sink cannot claim more than
    /// the documentation does.
    fn name(&self) -> &'static str;

    /// Where it sends. Nothing is sent anywhere else, and `render` reaches here not at all.
    fn destination(&self) -> &str;

    /// Exactly the bytes this sink would send for these events, without sending anything.
    ///
    /// This is what the tests assert on, and it is why a wire format can be checked on a computer
    /// with no network.
    fn render(&self, events: &[Event]) -> Result<Vec<u8>, String>;

    /// Sends them, and answers with the highest sequence the far end accepted.
    ///
    /// A sink that cannot tell which of a batch were accepted answers with the sequence before the
    /// batch, so nothing is ever marked exported on a guess.
    fn deliver<'a>(&'a self, ticket: &'a Ticket, events: &'a [Event], now: i64) -> Answer<'a, u64>;
}

/// The sentence a sink that has never been pointed at anything refuses with.
///
/// One sentence in one place, for the same reason `connector::reads_only` is one sentence in one
/// place: four sinks saying four different things about the same situation is four chances for one
/// of them to sound more finished than it is.
pub fn never_delivered(name: &str, why: &str) -> Trouble {
    Trouble::NotAllowed(format!(
        "{name} can render what it would send, and nothing in this grid has ever sent it. {why} Export to a syslog collector or an OpenTelemetry collector, which are built and exercised here, or carry the history out with the realm's own export."
    ))
}

/// What file extension a bundle is written with, so an operator and a runbook agree on what the
/// thing they are carrying is called.
pub const BUNDLE: &str = "grid-history.json";

/// Everything a realm has written and not yet got off this computer, ready to be carried away.
///
/// It names the realm it came from and the span it covers because an operator may be carrying
/// bundles out of several realms on several days, and a bundle that cannot say which realm and
/// which events it holds is one that can be handed back against the wrong one.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Bundle {
    /// Which realm wrote it. Checked on the way back in.
    pub realm_id: String,
    /// When it was written, by the clock the caller passed.
    pub written_at: i64,
    /// The sequence this realm had already got off the computer when this was written.
    pub after: u64,
    /// The last sequence in it, which is as far as the marker may move when it comes back.
    pub reaches: u64,
    pub events: Vec<Event>,
}

impl Bundle {
    /// How many events it holds.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Reads a bundle off a disk, and says plainly when the file is not one.
    pub fn read(from: &Path) -> Result<Bundle, String> {
        let bytes = std::fs::read(from).map_err(|error| format!("That history bundle could not be read: {error}"))?;
        serde_json::from_slice(&bytes).map_err(|_| "That file is not a history bundle this grid wrote".to_owned())
    }

    /// Writes it, and reads it back before calling it written.
    ///
    /// Reading it back is not ceremony. The whole point of a bundle is that it is the only copy of
    /// events that are about to be allowed out of the realm, so "the write call returned" is not
    /// enough: a short write, a full disk or a file somebody else is also writing all produce a
    /// file that exists and is not this. What is compared is the bundle that comes back off the
    /// disk, event for event and seal for seal.
    pub fn write(&self, to: &Path) -> Result<(), String> {
        if let Some(folder) = to.parent().filter(|folder| !folder.as_os_str().is_empty()) {
            std::fs::create_dir_all(folder).map_err(|error| format!("Cannot open the folder for the history bundle: {error}"))?;
        }
        let bytes = serde_json::to_vec_pretty(self).map_err(|error| format!("This grid could not write its history out: {error}"))?;
        super::store::room::enough_for(to, bytes.len() as u64, "for this grid's history bundle")?;
        // Asking the file system to make the file, rather than asking whether one is there and
        // then writing. The two are not the same: between the question and the answer somebody
        // else's file can appear at that path, and writing then destroys it. One call that makes
        // the file or fails is the only way to be sure this bundle is not written over something.
        let mut file = match std::fs::OpenOptions::new().write(true).create_new(true).open(to) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err("There is already a file where that history bundle would go".into())
            }
            Err(error) => return Err(format!("The history bundle could not be written: {error}")),
        };
        // Written, then put on the disk. A bundle is the one copy of events the realm may then be
        // allowed to drop, so the operator carrying it away has to be carrying what is actually on
        // the disk and not what is still in the computer's hands. A half-written file left behind
        // is cleared, because the next attempt would otherwise be refused by a file that is not a
        // bundle and that nobody meant to keep.
        let settled = std::io::Write::write_all(&mut file, &bytes).and_then(|()| file.sync_all());
        drop(file);
        if let Err(error) = settled {
            let _ = std::fs::remove_file(to);
            return Err(format!("The history bundle could not be written: {error}"));
        }
        let back = match Bundle::read(to) {
            Ok(back) => back,
            Err(said) => {
                let _ = std::fs::remove_file(to);
                return Err(said);
            }
        };
        if back.realm_id != self.realm_id || back.reaches != self.reaches || back.events.len() != self.events.len() {
            let _ = std::fs::remove_file(to);
            return Err("The history bundle on the disk is not the one this grid wrote. Nothing has been marked carried out.".into());
        }
        for (written, read) in self.events.iter().zip(back.events.iter()) {
            if written.sequence != read.sequence || written.seal != read.seal {
                let _ = std::fs::remove_file(to);
                return Err(format!("Event {} did not come back off the disk as it was written. Nothing has been marked carried out.", written.sequence));
            }
        }
        Ok(())
    }

    /// Whether this bundle is whole, under the realm's key.
    ///
    /// The same `Chain::verify` the realm holds itself to, so a bundle is held to exactly what the
    /// realm is held to and there is no second account of what a seal means.
    pub fn verify(&self, key: &str) -> Result<(), String> {
        if self.events.is_empty() {
            return Err("That history bundle holds no events".into());
        }
        if self.events.last().map(|event| event.sequence) != Some(self.reaches) {
            return Err("That history bundle says it reaches further than its own last event".into());
        }
        Chain { events: self.events.clone() }.verify(key)
    }
}

/// The severity a decision maps to. RFC 5424 section 6.2.1: 6 is informational, 4 is a warning.
/// A refusal is a warning and not an error, because a grid refusing something is the grid working.
fn severity(decision: Decision) -> u8 {
    match decision {
        Decision::Allowed => 6,
        Decision::Refused => 4,
    }
}

/// `2022-11-01T09:00:00Z`, which is what both of the built sinks want for a time.
fn rfc3339(at: i64) -> String {
    chrono::DateTime::from_timestamp(at, 0).unwrap_or_default().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// A structured data parameter value, escaped the way RFC 5424 section 6.3.3 says: a quote, a
/// backslash and a closing bracket are the three characters that end a parameter early.
fn sd_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for letter in text.chars().filter(|letter| !letter.is_control()) {
        if matches!(letter, '"' | '\\' | ']') {
            out.push('\\');
        }
        out.push(letter);
    }
    out
}

/// A printable ASCII field for the header of a syslog message. RFC 5424 says a header field is
/// printable ASCII with no spaces, and a hyphen means there is nothing to say. Anything that is
/// not that becomes a hyphen rather than being sent as something a collector cannot parse.
fn header_field(text: &str, longest: usize) -> String {
    let cleaned: String = text.chars().filter(|letter| letter.is_ascii_graphic()).take(longest).collect();
    if cleaned.is_empty() {
        "-".to_owned()
    } else {
        cleaned
    }
}

/// RFC 5424 messages, framed the way RFC 6587 section 3.4.1 describes, over a connection.
///
/// Octet counting rather than the older newline framing, because an audit reason is free text and
/// a newline in one would split a message in two at the collector. The count is the byte length of
/// the message and the test recomputes it.
pub struct Syslog {
    destination: String,
    /// What this computer calls itself to the collector.
    hostname: String,
    /// The facility, which is the first half of the priority. 13 is `log audit`, which is what
    /// this is, and naming it rather than using 1 for `user` is the difference between a
    /// collector filing these with the audit trail and filing them with everything else.
    facility: u8,
    realm_id: String,
}

impl Syslog {
    /// `log audit`, RFC 5424 table 1.
    pub const AUDIT_FACILITY: u8 = 13;

    pub fn new(destination: &str, hostname: &str, realm_id: &str) -> Result<Syslog, String> {
        let destination = destination.trim().trim_end_matches('/').to_owned();
        if destination.is_empty() || destination.len() > 512 || destination.chars().any(|letter| letter.is_control() || letter.is_whitespace()) {
            return Err("A syslog collector is one address, with no spaces in it".into());
        }
        Ok(Syslog { destination, hostname: header_field(hostname, 255), facility: Syslog::AUDIT_FACILITY, realm_id: realm_id.to_owned() })
    }

    /// One RFC 5424 message, without the frame around it.
    pub fn message(&self, event: &Event) -> String {
        let priority = u16::from(self.facility) * 8 + u16::from(severity(event.decision));
        let structured = format!(
            "[yougori@{PLACEHOLDER_ENTERPRISE_NUMBER} seq=\"{}\" realm=\"{}\" seal=\"{}\" previous=\"{}\" policy=\"{}\" decision=\"{}\"{}{}]",
            event.sequence,
            sd_escape(&self.realm_id),
            sd_escape(&event.seal),
            sd_escape(&event.previous_seal),
            event.policy_version,
            if event.decision == Decision::Allowed { "allowed" } else { "refused" },
            event.device_id.as_deref().map(|device| format!(" device=\"{}\"", sd_escape(device))).unwrap_or_default(),
            event.workload_id.as_deref().map(|work| format!(" work=\"{}\"", sd_escape(work))).unwrap_or_default(),
        );
        // The reason is the message, and it is the one part a person wrote. It has already been
        // through the realm's redaction gate on the way in, so what is left to do is keep it on
        // one line: a newline here would be read as the end of a message by a collector framing
        // on newlines, and this sink must render the same bytes whichever framing is in use.
        let said = event.reason.chars().filter(|letter| !letter.is_control()).take(480).collect::<String>();
        format!(
            "<{priority}>1 {} {} {APPLICATION} {} {} {structured} {}",
            rfc3339(event.at),
            self.hostname,
            header_field(&event.principal_id, 128),
            header_field(&event.action, 32),
            if said.is_empty() { event.action.clone() } else { said }
        )
    }
}

impl Sink for Syslog {
    fn name(&self) -> &'static str {
        "Syslog over TCP to a collector on this computer"
    }

    fn destination(&self) -> &str {
        &self.destination
    }

    fn render(&self, events: &[Event]) -> Result<Vec<u8>, String> {
        let mut out = Vec::new();
        for event in events {
            let message = self.message(event);
            out.extend_from_slice(format!("{} ", message.len()).as_bytes());
            out.extend_from_slice(message.as_bytes());
        }
        Ok(out)
    }

    fn deliver<'a>(&'a self, ticket: &'a Ticket, events: &'a [Event], now: i64) -> Answer<'a, u64> {
        Box::pin(async move {
            if !ticket.live(now) {
                return Err(Trouble::NotAllowed("This permission has expired. Ask for it again.".into()));
            }
            let Some(last) = events.last() else { return Ok(0) };
            let bytes = self.render(events).map_err(Trouble::Missing)?;
            // Syslog over a stream has no acknowledgement of any kind: RFC 5424 says so in terms.
            // What is proved by a write that returned is that the bytes left this computer, which
            // is the most this sink can ever honestly report, and it is why `exported_to` moving
            // means "sent", not "stored".
            send_bytes(&self.destination, &bytes).await.map_err(Trouble::Refused)?;
            Ok(last.sequence)
        })
    }
}

/// Writes bytes to a collector on a stream and waits for nothing back.
///
/// Plain TCP only to this computer, in the same way `https::parse` already allows plain HTTP only
/// to this computer. A collector anywhere else is reached over TLS, and that is not built here:
/// RFC 5425 is syslog inside TLS, and wiring it needs a client certificate path this grid's TLS
/// client does not have. A destination that is not on this computer is refused rather than sent to
/// in the clear.
async fn send_bytes(destination: &str, bytes: &[u8]) -> Result<(), String> {
    use tokio::io::AsyncWriteExt;
    let (host, _) = destination.rsplit_once(':').ok_or("A syslog collector is an address and a port, such as 127.0.0.1:6514")?;
    if !matches!(host, "127.0.0.1" | "localhost" | "::1" | "[::1]") {
        return Err(format!(
            "This grid sends syslog only to a collector on this computer. {host} is somewhere else, and reaching it would mean sending a sealed history over a plain connection, which this will not do."
        ));
    }
    let mut stream = tokio::time::timeout(std::time::Duration::from_secs(10), tokio::net::TcpStream::connect(destination))
        .await
        .map_err(|_| format!("{destination} did not answer in time"))?
        .map_err(|error| format!("{destination} could not be reached: {error}"))?;
    stream.write_all(bytes).await.map_err(|error| format!("The history could not be written to {destination}: {error}"))?;
    stream.flush().await.map_err(|error| format!("The history could not be written to {destination}: {error}"))?;
    Ok(())
}

/// OpenTelemetry logs, OTLP over HTTP with JSON encoding.
///
/// Over HTTP and not gRPC, and that is a decision rather than a shortcut. OTLP over gRPC needs
/// protobuf and a gRPC stack, neither of which is in this build, and a hand-rolled one could not
/// be verified against anything here. OTLP over HTTP with JSON encoding is a published mapping
/// that a test can assert field by field, which is the whole reason this one is built.
pub struct Otlp {
    destination: String,
    realm_id: String,
}

impl Otlp {
    pub fn new(destination: &str, realm_id: &str) -> Result<Otlp, String> {
        let destination = destination.trim().trim_end_matches('/').to_owned();
        crate::https::parse(&destination)?;
        Ok(Otlp { destination, realm_id: realm_id.to_owned() })
    }

    /// Where the logs go. The specification fixes this path, so it is here and not a setting.
    pub const PATH: &'static str = "/v1/logs";

    fn attribute(key: &str, value: serde_json::Value) -> serde_json::Value {
        serde_json::json!({"key": key, "value": value})
    }

    fn text(value: &str) -> serde_json::Value {
        serde_json::json!({"stringValue": value})
    }

    /// The body, as the proto3 JSON mapping of `ExportLogsServiceRequest`.
    pub fn body(&self, events: &[Event]) -> serde_json::Value {
        let records: Vec<serde_json::Value> = events
            .iter()
            .map(|event| {
                let mut attributes = vec![
                    // A 64-bit integer is a string in proto3 JSON, and a sequence number is one.
                    Otlp::attribute("yougori.sequence", serde_json::json!({"stringValue": event.sequence.to_string()})),
                    Otlp::attribute("yougori.seal", Otlp::text(&event.seal)),
                    Otlp::attribute("yougori.previous_seal", Otlp::text(&event.previous_seal)),
                    Otlp::attribute("yougori.policy_version", serde_json::json!({"stringValue": event.policy_version.to_string()})),
                    Otlp::attribute("yougori.decision", Otlp::text(if event.decision == Decision::Allowed { "allowed" } else { "refused" })),
                    Otlp::attribute("enduser.id", Otlp::text(&event.principal_id)),
                ];
                for (key, value) in [("device.id", event.device_id.as_deref()), ("yougori.workload", event.workload_id.as_deref()), ("yougori.resource", event.resource_id.as_deref()), ("yougori.command", event.command.as_deref())] {
                    if let Some(value) = value {
                        attributes.push(Otlp::attribute(key, Otlp::text(value)));
                    }
                }
                serde_json::json!({
                    // Nanoseconds since the epoch, as a string: proto3 JSON encodes a 64-bit
                    // integer as a string, and a collector reading a number here loses precision
                    // or rejects the record outright.
                    "timeUnixNano": (event.at as i128 * 1_000_000_000).to_string(),
                    "observedTimeUnixNano": (event.at as i128 * 1_000_000_000).to_string(),
                    "severityNumber": if event.decision == Decision::Allowed { 9 } else { 13 },
                    "severityText": if event.decision == Decision::Allowed { "INFO" } else { "WARN" },
                    "body": {"stringValue": if event.reason.is_empty() { event.action.clone() } else { event.reason.clone() }},
                    "attributes": attributes,
                })
            })
            .collect();
        serde_json::json!({
            "resourceLogs": [{
                "resource": {"attributes": [
                    Otlp::attribute("service.name", Otlp::text(APPLICATION)),
                    Otlp::attribute("service.instance.id", Otlp::text(&self.realm_id)),
                    Otlp::attribute("service.version", Otlp::text(env!("CARGO_PKG_VERSION"))),
                ]},
                "scopeLogs": [{
                    "scope": {"name": "yougori.grid.audit"},
                    "logRecords": records,
                }],
            }]
        })
    }
}

impl Sink for Otlp {
    fn name(&self) -> &'static str {
        "OpenTelemetry"
    }

    fn destination(&self) -> &str {
        &self.destination
    }

    fn render(&self, events: &[Event]) -> Result<Vec<u8>, String> {
        Ok(self.body(events).to_string().into_bytes())
    }

    fn deliver<'a>(&'a self, ticket: &'a Ticket, events: &'a [Event], now: i64) -> Answer<'a, u64> {
        Box::pin(async move {
            if !ticket.live(now) {
                return Err(Trouble::NotAllowed("This permission has expired. Ask for it again.".into()));
            }
            let Some(last) = events.last() else { return Ok(0) };
            let bytes = self.render(events).map_err(Trouble::Missing)?;
            let url = format!("{}{}", self.destination, Otlp::PATH);
            let answer = crate::https::call("POST", &url, &[], Some(("application/json", bytes)), super::connector::wire::WAIT).await.map_err(Trouble::Refused)?;
            if !answer.ok() {
                return Err(Trouble::Refused(format!("The collector did not take this batch: {}", answer.said())));
            }
            // A partial success is the collector saying it kept some and dropped others, and it
            // names how many it dropped rather than which. Nothing can be marked exported on that,
            // because the marker is a sequence number and "some of these" is not one.
            //
            // proto3 JSON writes a 64-bit integer as a string, but its parsers have to take a
            // number as well, and real collectors send both. A count this cannot read is treated
            // as a refusal rather than as nothing dropped: moving the marker on a count nobody
            // understood is how the records the collector threw away get trimmed off this
            // computer too, leaving them nowhere at all.
            let rejected = match &answer.json()["partialSuccess"]["rejectedLogRecords"] {
                serde_json::Value::Null => Some(0),
                serde_json::Value::String(count) => count.parse::<u64>().ok(),
                other => other.as_u64(),
            };
            let Some(rejected) = rejected else {
                return Err(Trouble::Refused(
                    "The collector said it kept part of this batch and gave a count this grid could not read. Nothing has been marked exported.".into(),
                ));
            };
            if rejected > 0 {
                return Err(Trouble::Refused(format!(
                    "The collector kept part of this batch and dropped {rejected} records, and it does not say which. Nothing has been marked exported."
                )));
            }
            Ok(last.sequence)
        })
    }
}

/// What a vendor envelope is, when all this repository can do is render one.
///
/// Four of these, and they share everything but the shape of the body, so they are one type with
/// the shape as a field. Four near-identical files would be four places for the refusal sentence
/// to drift apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Envelope {
    /// A generic SIEM webhook: newline-delimited JSON, one event a line.
    Webhook,
    /// Splunk HTTP Event Collector: concatenated JSON objects, each wrapping the event.
    SplunkHec,
    /// Elasticsearch `_bulk`: alternating action and document lines, with a trailing newline.
    Elastic,
    /// Microsoft Sentinel's logs ingestion API: one JSON array, times in RFC 3339.
    Sentinel,
}

impl Envelope {
    pub fn row(self) -> &'static str {
        match self {
            Envelope::Webhook => "SIEM webhook",
            Envelope::SplunkHec => "Splunk",
            Envelope::Elastic => "Elastic",
            Envelope::Sentinel => "Microsoft Sentinel",
        }
    }

    /// The path the vendor documents. Rendered into the refusal so an administrator reading it can
    /// see what this would have sent and where.
    pub fn path(self) -> &'static str {
        match self {
            Envelope::Webhook => "whatever path the webhook names",
            Envelope::SplunkHec => "/services/collector/event",
            Envelope::Elastic => "/{data stream}/_bulk",
            Envelope::Sentinel => "/dataCollectionRules/{rule}/streams/{stream}?api-version=2023-01-01",
        }
    }

    /// Why nothing here has ever delivered one, said once per vendor and said plainly.
    fn why(self) -> &'static str {
        match self {
            Envelope::Webhook => "A webhook's signature is an HMAC over the body with a key from the vault, and nothing in this grid hands a key out for a caller to sign arbitrary bytes with, so the signing has nowhere to happen yet.",
            Envelope::SplunkHec => "Whether the index exists, whether the token is scoped to it and whether the service accepts the batch cannot be known from this repository.",
            Envelope::Elastic => "Whether the data stream exists and whether the credential may write to it cannot be known from this repository.",
            Envelope::Sentinel => "Whether the data collection rule is bound to this stream, and whether the token's scope covers it, cannot be known from this repository.",
        }
    }
}

/// A vendor envelope, rendered and never sent.
pub struct Vendor {
    envelope: Envelope,
    destination: String,
    realm_id: String,
    /// The Elastic data stream or the Splunk index, whichever this vendor calls it. Named rather
    /// than defaulted, because an envelope that quietly writes to `logs-generic-default` is an
    /// envelope nobody asked for.
    stream: String,
}

impl Vendor {
    pub fn new(envelope: Envelope, destination: &str, realm_id: &str, stream: &str) -> Result<Vendor, String> {
        let destination = destination.trim().trim_end_matches('/').to_owned();
        crate::https::parse(&destination)?;
        let stream = crate::label(stream, "stream")?;
        Ok(Vendor { envelope, destination, realm_id: realm_id.to_owned(), stream })
    }

    pub fn envelope(&self) -> Envelope {
        self.envelope
    }

    /// One event as a flat object, which is what every one of these four wraps.
    fn flat(&self, event: &Event) -> serde_json::Value {
        serde_json::json!({
            "sequence": event.sequence,
            "at": rfc3339(event.at),
            "realm": self.realm_id,
            "principal": event.principal_id,
            "device": event.device_id,
            "workload": event.workload_id,
            "action": event.action,
            "resource": event.resource_id,
            "policyVersion": event.policy_version,
            "decision": if event.decision == Decision::Allowed { "allowed" } else { "refused" },
            "reason": event.reason,
            "command": event.command,
            "seal": event.seal,
            "previousSeal": event.previous_seal,
        })
    }
}

impl Sink for Vendor {
    fn name(&self) -> &'static str {
        self.envelope.row()
    }

    fn destination(&self) -> &str {
        &self.destination
    }

    fn render(&self, events: &[Event]) -> Result<Vec<u8>, String> {
        let mut out = String::new();
        match self.envelope {
            Envelope::Webhook => {
                for event in events {
                    out.push_str(&self.flat(event).to_string());
                    out.push('\n');
                }
            }
            Envelope::SplunkHec => {
                for event in events {
                    // Splunk takes concatenated objects with no separator at all, which is the
                    // detail people get wrong by putting commas between them.
                    out.push_str(&serde_json::json!({"time": event.at, "host": APPLICATION, "source": APPLICATION, "sourcetype": "_json", "index": self.stream, "event": self.flat(event)}).to_string());
                }
            }
            Envelope::Elastic => {
                for event in events {
                    out.push_str(&serde_json::json!({"create": {"_index": self.stream}}).to_string());
                    out.push('\n');
                    out.push_str(&self.flat(event).to_string());
                    out.push('\n');
                }
                // The bulk API needs the last line to end with a newline, and a body that does not
                // is rejected whole. The loop above already ends with one; this is the empty case.
                if events.is_empty() {
                    out.push('\n');
                }
            }
            Envelope::Sentinel => {
                let rows: Vec<serde_json::Value> = events
                    .iter()
                    .map(|event| {
                        let mut row = self.flat(event);
                        row["TimeGenerated"] = serde_json::Value::String(rfc3339(event.at));
                        row
                    })
                    .collect();
                out.push_str(&serde_json::Value::Array(rows).to_string());
            }
        }
        Ok(out.into_bytes())
    }

    fn deliver<'a>(&'a self, _ticket: &'a Ticket, _events: &'a [Event], _now: i64) -> Answer<'a, u64> {
        Box::pin(async move { Err(never_delivered(self.envelope.row(), self.envelope.why())) })
    }
}

