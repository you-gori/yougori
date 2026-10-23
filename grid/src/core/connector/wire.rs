//! One request, with a credential the connector never sees.
//!
//! The four desktop connectors read their value through `desktop::Keyring` because the code that
//! makes their requests is `provisioning::Task`, which was written before this seam and is left
//! exactly as it was. Every connector written since goes through here instead, and the difference
//! is worth stating plainly: a connector is built with a `Box<dyn Wire>`, and `Wire` has no method
//! that returns a value. It is not that a new connector is written carefully enough not to hold a
//! secret. There is nothing it could call to get one.
//!
//! What that costs is that the value handling moves here, because somebody has to do it. Three
//! kinds of handling turn up across the providers in this phase and all three are in `Present`:
//! putting the value on the request as it is, signing the request with it, and exchanging it for a
//! short-lived token. A connector names none of them. It is given a wire that already knows, and
//! it asks for a method, a path and a body.
//!
//! This is not a second credential broker. `core::broker` is how a *workload* makes a request with
//! a credential it never sees: it goes out through the Access Grid's forwarder, with a
//! single-use permission per request, a destination allowlist and a ledger row. That path presents
//! a credential; it does not sign a request with one or exchange one for a token, which is what
//! every provider in this phase needs. So a connector takes the same road the four that already
//! ship take, `crate::https`, which is the client `provisioning.rs` has used all along, and this
//! file is the one place on that road where a value exists.
//!
//! The rate limit, the breaker and the token cache all live here too, for the same reason: they
//! are about one connection to one provider, and a connector that had to remember them would be a
//! connector that could forget them.
use super::{admits, limits::{retry_after, Breaker, Budget, Gate}, Answer, Ticket, Trouble};
use crate::https;
use bytes::Bytes;
use serde_json::Value;
use std::sync::Mutex;
use std::time::Duration;

/// How long one call to a provider waits. The same minute `access::forward` waits, because a
/// person watching a screen has the same patience whichever road the request took.
pub const WAIT: Duration = Duration::from_secs(60);

/// What a credential turned out to be, and which version of the vault entry answered.
///
/// The version is here and not only in the vault because a note has to be able to say which
/// version of a credential authorised a request. That is what makes a rotation visible in the
/// history without the value ever being.
pub struct Opened {
    pub fields: Value,
    pub version: u32,
}

/// Where a connector's secret comes from.
///
/// Deliberately not part of the `Connector` trait and deliberately not reachable from a `Wire`: a
/// wire is built with one, and nothing on `Wire` hands one back. `desktop::Keyring` is the same
/// idea for the four wrapped connectors and is left where it is, because moving it would change a
/// trait their tests construct and buy nothing.
pub trait Keys: Send + Sync {
    /// The secret fields of one credential, by the name the realm knows it under.
    fn open(&self, credential_id: &str) -> Result<Opened, String>;
}

/// What goes in a request body.
#[derive(Clone, Debug)]
pub enum Body {
    Json(Value),
    Form(Vec<(String, String)>),
    Bytes { content_type: &'static str, bytes: Vec<u8> },
}

impl Body {
    fn parts(&self) -> (&'static str, Vec<u8>) {
        match self {
            Body::Json(value) => ("application/json", value.to_string().into_bytes()),
            Body::Form(fields) => ("application/x-www-form-urlencoded", https::encode_form(&fields.iter().map(|(name, value)| (name.as_str(), value.as_str())).collect::<Vec<_>>()).into_bytes()),
            Body::Bytes { content_type, bytes } => (content_type, bytes.clone()),
        }
    }
}

/// One request a connector wants made, relative to the destination its wire is pointed at.
///
/// There is no field for a host. A connector cannot choose where its credential is spent, and that
/// is a fact about this type rather than a check somewhere.
#[derive(Clone, Debug)]
pub struct Call {
    pub method: &'static str,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(&'static str, String)>,
    pub body: Option<Body>,
    /// Whether the credential goes on this request. A discovery document or a version listing is
    /// public at several of these providers, and asking for one should not spend a credential.
    pub authorise: bool,
}

impl Call {
    pub fn get(path: &str) -> Call {
        Call { method: "GET", path: path.to_owned(), query: Vec::new(), headers: Vec::new(), body: None, authorise: true }
    }

    pub fn of(method: &'static str, path: &str) -> Call {
        Call { method, path: path.to_owned(), ..Call::get(path) }
    }

    pub fn with(mut self, name: &str, value: &str) -> Call {
        self.query.push((name.to_owned(), value.to_owned()));
        self
    }

    pub fn header(mut self, name: &'static str, value: &str) -> Call {
        self.headers.push((name, value.to_owned()));
        self
    }

    pub fn json(mut self, body: Value) -> Call {
        self.body = Some(Body::Json(body));
        self
    }

    /// The query string as it goes on the wire, which is also what a signature is taken over.
    fn query_string(&self) -> Option<String> {
        if self.query.is_empty() {
            return None;
        }
        Some(self.query.iter().map(|(name, value)| format!("{}={}", https::encode(name), https::encode(value))).collect::<Vec<_>>().join("&"))
    }
}

/// What a provider answered.
#[derive(Clone, Debug)]
pub struct Reply {
    pub status: u16,
    pub body: Bytes,
    /// How long the provider said to wait, when it said anything. Only this one header is carried
    /// up out of the answer, because it is the only one a connector's behaviour turns on, and a
    /// `Reply` that carried every header would be a `Reply` a connector could read a token or a
    /// cookie out of.
    pub retry_after: Option<i64>,
}

impl Reply {
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap_or(Value::Null)
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The status and a short printable piece of what came back, for a note shown to an
    /// administrator. Never a whole document, the same shape `https::Answer::said` already uses.
    pub fn said(&self) -> String {
        let json = self.json();
        let message = json["error"]["message"]
            .as_str()
            .or_else(|| json["error"]["code"].as_str())
            .or_else(|| json["message"].as_str())
            .or_else(|| json["error_description"].as_str())
            .map(str::to_owned)
            .or_else(|| xml_text(&self.text(), "Message"))
            .unwrap_or_else(|| self.text().chars().filter(|letter| !letter.is_control()).take(160).collect());
        format!("HTTP {}: {}", self.status, message.chars().take(200).collect::<String>())
    }

    /// Whether the provider says this is already true. A conflict is the answer every provider in
    /// this phase gives for a change that has already been made, which is what makes carrying a
    /// plan out twice safe.
    pub fn already(&self) -> bool {
        self.status == 409
    }

    /// Whether the provider is shedding this grid's requests.
    ///
    /// 429 is the status RFC 6585 defines for exactly this, so it counts on its own. 503 counts
    /// only when the provider also said when to come back, and that line is drawn deliberately: a
    /// 503 with a `Retry-After` is a service saying it is busy and naming a time, which is a
    /// throttle, and a 503 with nothing on it is a service that is simply not working, which is
    /// what the refusal breaker is for. Treating every 503 as a throttle would stop a connection
    /// for thirty seconds the first time a provider had a bad minute, and treating none of them as
    /// one would ignore a time the provider went out of its way to give.
    pub fn throttled(&self) -> bool {
        self.status == 429 || (self.status == 503 && self.retry_after.is_some())
    }
}

/// One element's text out of an XML answer. AWS answers EC2 and S3 in XML and there is no XML
/// parser in this tree; what is needed is one element at a time, which this does without pretending
/// to be a parser. `access::sigv4::xml_text` does the same thing for STS and is another session's
/// file, so it is read rather than changed.
pub fn xml_text(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&format!("</{tag}>"))? + start;
    Some(xml[start..end].trim().replace("&amp;", "&").replace("&lt;", "<").replace("&gt;", ">").replace("&quot;", "\"").replace("&apos;", "'"))
}

/// Every occurrence of one element, in order.
pub fn xml_all(xml: &str, tag: &str) -> Vec<String> {
    let (open, close) = (format!("<{tag}>"), format!("</{tag}>"));
    let mut found = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find(&open) {
        let from = start + open.len();
        let Some(end) = rest[from..].find(&close) else { break };
        found.push(rest[from..from + end].to_owned());
        rest = &rest[from + end + close.len()..];
    }
    found
}

/// How one connection presents its credential.
///
/// Decided once, when the connection is made, because one connector reaches one provider with one
/// credential in one way. A `Call` therefore says only whether the credential goes on it at all,
/// and a connector never chooses a presentation, an endpoint to sign in at or a signing key.
#[derive(Clone, Debug)]
pub enum Present {
    /// `Authorization: Bearer <field>`.
    Bearer { field: String },
    /// A named header carrying the field as it is, such as an API key header.
    Header { name: String, field: String },
    /// AWS Signature Version 4, signed here over the request as it will go out.
    AwsSigV4 { service: String, region: String, access_field: String, secret_field: String },
    /// Azure Storage shared key: an HMAC over a canonicalised description of the request.
    AzureSharedKey { account: String, field: String },
    /// OAuth 2 client credentials: the value is a client secret, exchanged at `token_url` for a
    /// short-lived access token which is what actually goes on the request.
    ClientCredentials { token_url: String, client_id: String, scope: String, field: String },
    /// OpenStack Keystone v3: the value is a password, exchanged at `auth_url` for a token that
    /// comes back in the `X-Subject-Token` header.
    Keystone { auth_url: String, user: String, user_domain: String, project: String, project_domain: String, field: String },
}

impl Present {
    /// What an administrator is told this connection does with its credential. No value, and no
    /// field name that would say more than the kind.
    pub fn describe(&self) -> &'static str {
        match self {
            Present::Bearer { .. } => "sends the credential as a bearer token",
            Present::Header { .. } => "sends the credential in a header the provider names",
            Present::AwsSigV4 { .. } => "signs each request with the credential and sends no key",
            Present::AzureSharedKey { .. } => "signs each request with the account key and sends no key",
            Present::ClientCredentials { .. } => "exchanges the credential for a short-lived token and sends that",
            Present::Keystone { .. } => "exchanges the credential for a short-lived token and sends that",
        }
    }

    /// Whether the value itself ever leaves this computer, or only something made from it.
    pub fn sends_the_value(&self) -> bool {
        matches!(self, Present::Bearer { .. } | Present::Header { .. })
    }

}

/// Makes one request with a credential the caller never sees.
///
/// Three methods and not one of them hands anything back that could be replayed. A connector holds
/// a `Box<dyn Wire>` and there is no call on it that could produce a value.
pub trait Wire: Send + Sync {
    /// Where this wire sends, which a connector cannot change.
    fn destination(&self) -> &str;

    /// Makes one request. The permission is checked against the destination first, so a permission
    /// minted for one provider is never spent at another.
    fn send<'a>(&'a self, ticket: &'a Ticket, call: Call, now: i64) -> Answer<'a, Reply>;

    /// Which version of the vault entry authorised the last request that went out, so a note can
    /// say which version did what. Nothing before the first request has an answer.
    fn version_used(&self) -> Option<u32>;
}

/// A token this wire minted, and when it stops being usable.
#[derive(Clone)]
struct Minted {
    token: String,
    until: i64,
    /// Which version of the credential it was minted from. A rotation retires it rather than
    /// letting a token made from the old value outlive the value.
    version: u32,
}

#[derive(Default)]
struct State {
    minted: Option<Minted>,
    version_used: Option<u32>,
}

/// The wire this computer runs: the vault, the signing, the token, the budget and the breaker, in
/// the one place that is allowed to see a value.
pub struct Keyed {
    destination: String,
    /// The address requests actually go to. The same as the destination for every provider whose
    /// API lives at the address a permission names, and different for an appliance whose API lives
    /// under its own address, which is why `desktop::DesktopService` already keeps the two apart.
    base: String,
    present: Present,
    keys: Box<dyn Keys>,
    budget: Mutex<Budget>,
    breaker: Mutex<Breaker>,
    gate: Gate,
    state: Mutex<State>,
}

impl std::fmt::Debug for Keyed {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the keys, never a token, never a field name that reads like a value.
        formatter.debug_struct("Keyed").field("destination", &self.destination).field("presents", &self.present.describe()).finish()
    }
}

impl Keyed {
    /// A wire for one connection.
    ///
    /// `destination` is where the credential may be spent and is what a permission has to name.
    /// `base` is the address the requests go to; it is the same thing for a public cloud and a
    /// different thing for an appliance, which is the distinction `desktop.rs` already makes.
    pub fn new(destination: &str, base: &str, present: Present, keys: Box<dyn Keys>, now: i64) -> Result<Keyed, String> {
        let destination = destination.trim().trim_end_matches('/').to_owned();
        if !destination.starts_with("https://") || destination.len() > 512 || destination.chars().any(|letter| letter.is_control() || letter.is_whitespace()) {
            return Err("A connector's destination is one https:// address".into());
        }
        let base = base.trim().trim_end_matches('/').to_owned();
        let (secure, host, _, _) = https::parse(&base)?;
        if !secure && !matches!(host.as_str(), "127.0.0.1" | "localhost" | "::1") {
            return Err("A connection's address is an https:// address, unless it is a server on this computer".into());
        }
        if super::carries_a_value(&destination) || super::carries_a_value(&base) {
            return Err("An address is where something is, not a way into it. Put the secret in this computer's vault.".into());
        }
        Ok(Keyed { destination, base, present, keys, budget: Mutex::new(Budget::standard(now)), breaker: Mutex::new(Breaker::new()), gate: Gate::standard(), state: Mutex::new(State::default()) })
    }

    /// What this connection does with its credential, for showing an administrator.
    pub fn presents(&self) -> &'static str {
        self.present.describe()
    }

    /// Whether the value itself ever leaves this computer, or only something made from it.
    pub fn sends_the_value(&self) -> bool {
        self.present.sends_the_value()
    }

    /// One field out of what the vault answered, named so the sentence says which one is missing
    /// without saying anything about what is in it.
    fn field<'a>(fields: &'a Value, name: &str) -> Result<&'a str, Trouble> {
        fields[name].as_str().filter(|value| !value.is_empty()).ok_or_else(|| Trouble::Missing(format!("The credential in this computer's vault has no {name}. Enter it again.")))
    }

    /// Whether anything may go out right now: the breaker is shut and the budget has a token.
    fn may_send(&self, now: i64) -> Result<(), Trouble> {
        self.breaker.lock().map_err(|_| Trouble::Refused("This connection is in an unusable state and was not used".into()))?.allow(now)?;
        let wait = {
            let mut budget = self.budget.lock().map_err(|_| Trouble::Refused("This connection is in an unusable state and was not used".into()))?;
            budget.take(now).err()
        };
        match wait {
            None => Ok(()),
            Some(seconds) => Err(Trouble::Refused(format!(
                "This connection has made as many requests as it allows itself for the moment. Try again in {seconds} seconds. Nothing was sent."
            ))),
        }
    }

    fn answered(&self, reply: &Reply, now: i64) {
        if let Ok(mut breaker) = self.breaker.lock() {
            // A provider that answered at all is a provider that is up. Its own refusal of one
            // request is the connector's business, not the breaker's, and treating a 404 as a
            // reason to stop sending would make one wrong path look like an outage.
            if reply.status >= 500 {
                breaker.failed(now);
            } else if !reply.throttled() {
                breaker.succeeded();
            }
            // A throttle stops this connection sending for as long as the provider asked for, and
            // it is handled after the two lines above rather than instead of them: a 503 is both a
            // failure and a throttle, and counting it as a failure is what gets a provider that
            // never recovers to the refusal breaker. What a throttle must never do is call
            // `succeeded`, which would forget every refusal before it, which is exactly what
            // treating 429 as "the provider answered" used to do.
            if reply.throttled() {
                breaker.throttled(reply.retry_after, now);
            }
        }
    }

    fn unreachable(&self, now: i64) {
        if let Ok(mut breaker) = self.breaker.lock() {
            breaker.failed(now);
        }
    }

    /// The token this connection sends, minted if there is not a live one made from the version of
    /// the credential that is in the vault now.
    async fn token(&self, credential_id: &str, now: i64) -> Result<(String, u32), Trouble> {
        let opened = self.keys.open(credential_id).map_err(Trouble::NotAllowed)?;
        if let Ok(state) = self.state.lock() {
            if let Some(minted) = &state.minted {
                if minted.until > now && minted.version == opened.version {
                    return Ok((minted.token.clone(), minted.version));
                }
            }
        }
        let (token, lasts) = self.mint(&opened.fields, now).await?;
        if let Ok(mut state) = self.state.lock() {
            state.minted = Some(Minted { token: token.clone(), until: now + lasts, version: opened.version });
        }
        Ok((token, opened.version))
    }

    /// The one exchange of a value for a short-lived token, in the shape the provider documents.
    async fn mint(&self, fields: &Value, now: i64) -> Result<(String, i64), Trouble> {
        let _ = now;
        match &self.present {
            Present::ClientCredentials { token_url, client_id, scope, field } => {
                let secret = Keyed::field(fields, field)?;
                let answer = https::form(token_url, &[("grant_type", "client_credentials"), ("client_id", client_id), ("client_secret", secret), ("scope", scope)], &[], WAIT)
                    .await
                    .map_err(Trouble::Refused)?;
                if !answer.ok() {
                    return Err(Trouble::NotAllowed(format!("This connection could not sign in: {}", answer.said())));
                }
                let body = answer.json();
                let token = body["access_token"].as_str().ok_or_else(|| Trouble::Refused("The sign-in answered without a token".to_owned()))?.to_owned();
                // Short of what the provider says, so a token is never used in the last minute of
                // its life, when the clocks at the two ends may not agree.
                let lasts = body["expires_in"].as_i64().unwrap_or(3_600).clamp(60, 24 * 3_600) - 60;
                Ok((token, lasts.max(30)))
            }
            Present::Keystone { auth_url, user, user_domain, project, project_domain, field } => {
                let password = Keyed::field(fields, field)?;
                let ask = serde_json::json!({"auth": {
                    "identity": {"methods": ["password"], "password": {"user": {"name": user, "domain": {"name": user_domain}, "password": password}}},
                    "scope": {"project": {"name": project, "domain": {"name": project_domain}}}
                }});
                let answer = https::json("POST", &format!("{auth_url}/v3/auth/tokens"), None, &[], Some(&ask), WAIT).await.map_err(Trouble::Refused)?;
                if !answer.ok() {
                    return Err(Trouble::NotAllowed(format!("This connection could not sign in: {}", answer.said())));
                }
                // Keystone puts the token in a header and the catalogue in the body, which is the
                // one place in this file where the answer's headers matter.
                let token = answer.header("x-subject-token").ok_or_else(|| Trouble::Refused("Keystone answered without an X-Subject-Token header, so there is no token to use".to_owned()))?;
                // Keystone's own default is an hour. The expiry is in the body in a format this
                // file does not parse, so what is taken is the documented default less a few
                // minutes rather than a time nobody checked.
                Ok((token.to_owned(), 3_000))
            }
            _ => Err(Trouble::NotAllowed("This connection does not sign in; it presents its credential on each request".into())),
        }
    }

    /// Everything that puts a credential on one request, in the one place it happens.
    ///
    /// It returns the headers to add and the version of the credential they came from. The value
    /// itself is a local in this function and in `mint`, and neither hands one back.
    async fn authorise(&self, credential_id: &str, call: &Call, payload: &[u8], now: i64) -> Result<(Vec<(String, String)>, u32), Trouble> {
        match &self.present {
            Present::Bearer { field } => {
                let opened = self.keys.open(credential_id).map_err(Trouble::NotAllowed)?;
                Ok((vec![("authorization".to_owned(), format!("Bearer {}", Keyed::field(&opened.fields, field)?))], opened.version))
            }
            Present::Header { name, field } => {
                let opened = self.keys.open(credential_id).map_err(Trouble::NotAllowed)?;
                Ok((vec![(name.to_ascii_lowercase(), Keyed::field(&opened.fields, field)?.to_owned())], opened.version))
            }
            Present::AwsSigV4 { service, region, access_field, secret_field } => {
                let opened = self.keys.open(credential_id).map_err(Trouble::NotAllowed)?;
                let keys = crate::access::sigv4::Keys {
                    access_key: Keyed::field(&opened.fields, access_field)?.to_owned(),
                    secret_key: Keyed::field(&opened.fields, secret_field)?.to_owned(),
                    session_token: opened.fields["sessionToken"].as_str().map(str::to_owned),
                };
                let (_, host, port, _) = https::parse(&self.base).map_err(Trouble::Missing)?;
                let authority = if port == 443 || port == 80 { host } else { format!("{host}:{port}") };
                let signed = crate::access::sigv4::sign(call.method, &authority, &call.path, call.query_string().as_deref(), payload, &keys, region, service, &amz_date(now), true);
                Ok((signed, opened.version))
            }
            Present::AzureSharedKey { account, field } => {
                let opened = self.keys.open(credential_id).map_err(Trouble::NotAllowed)?;
                let key = Keyed::field(&opened.fields, field)?;
                let date = http_date(now);
                let mut headers = vec![("x-ms-date".to_owned(), date), ("x-ms-version".to_owned(), AZURE_STORAGE_VERSION.to_owned())];
                let signature = azure_shared_key(key, account, call, payload, &headers)?;
                headers.push(("authorization".to_owned(), format!("SharedKey {account}:{signature}")));
                Ok((headers, opened.version))
            }
            Present::ClientCredentials { .. } | Present::Keystone { .. } => {
                let (token, version) = self.token(credential_id, now).await?;
                let name = if matches!(self.present, Present::Keystone { .. }) { "x-auth-token" } else { "authorization" };
                let value = if name == "authorization" { format!("Bearer {token}") } else { token };
                Ok((vec![(name.to_owned(), value)], version))
            }
        }
    }
}

/// Which version of the Azure Storage API these requests are written against. Named rather than
/// repeated, because the signature's shape depends on it.
pub const AZURE_STORAGE_VERSION: &str = "2021-12-02";

/// `YYYYMMDDTHHMMSSZ` for a given moment, which is what SigV4 signs over. Taken from the moment
/// the caller passed rather than from a clock of this file's own, so a signature is reproducible.
pub fn amz_date(now: i64) -> String {
    chrono::DateTime::from_timestamp(now, 0).unwrap_or_default().format("%Y%m%dT%H%M%SZ").to_string()
}

/// `Tue, 01 Nov 2022 09:00:00 GMT`, which is what an Azure Storage signature is taken over.
pub fn http_date(now: i64) -> String {
    chrono::DateTime::from_timestamp(now, 0).unwrap_or_default().format("%a, %d %b %Y %H:%M:%S GMT").to_string()
}

/// The Azure Storage shared key signature over one request.
///
/// The string that is signed is the one Microsoft documents, in its order, with the headers this
/// grid owns canonicalised and the resource built from the account and the path. The empty lines
/// are the headers this grid never sets, and they are empty on purpose rather than missing: the
/// shape of the string is the agreement, and leaving a line out shifts every line after it.
fn azure_shared_key(key: &str, account: &str, call: &Call, payload: &[u8], extra: &[(String, String)]) -> Result<String, Trouble> {
    use base64::Engine;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    let decoded = base64::engine::general_purpose::STANDARD.decode(key).map_err(|_| Trouble::Missing("The account key in this computer's vault is not base64, which is what Azure Storage keys are".to_owned()))?;
    let length = if payload.is_empty() { String::new() } else { payload.len().to_string() };
    let content_type = call.body.as_ref().map(|body| body.parts().0).unwrap_or_default();
    let mut owned: Vec<(String, String)> = extra.iter().filter(|(name, _)| name.starts_with("x-ms-")).cloned().collect();
    owned.sort();
    let canonical_headers: String = owned.iter().map(|(name, value)| format!("{name}:{}\n", value.trim())).collect();
    let mut query: Vec<(String, String)> = call.query.iter().map(|(name, value)| (name.to_ascii_lowercase(), value.clone())).collect();
    query.sort();
    let canonical_resource = format!("/{account}{}{}", call.path, query.iter().map(|(name, value)| format!("\n{name}:{value}")).collect::<String>());
    let to_sign = format!("{}\n\n\n{length}\n\n{content_type}\n\n\n\n\n\n\n{canonical_headers}{canonical_resource}", call.method);
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&decoded).map_err(|_| Trouble::Missing("The account key in this computer's vault cannot be used for signing".to_owned()))?;
    mac.update(to_sign.as_bytes());
    Ok(base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()))
}

impl Wire for Keyed {
    fn destination(&self) -> &str {
        &self.destination
    }

    fn send<'a>(&'a self, ticket: &'a Ticket, call: Call, now: i64) -> Answer<'a, Reply> {
        Box::pin(async move {
            admits(ticket, &self.destination, now)?;
            self.may_send(now)?;
            // Held until this call is finished with, however it finishes. Taken after the budget
            // and the breaker, because those two refuse without reaching anybody and there is no
            // reason to hold a place for a request that is not going out.
            let _place = self.gate.enter()?;
            let (content_type, payload) = call.body.as_ref().map(|body| body.parts()).unwrap_or(("", Vec::new()));
            let mut headers: Vec<(String, String)> = call.headers.iter().map(|(name, value)| ((*name).to_owned(), value.clone())).collect();
            let mut version = None;
            if call.authorise {
                let (added, used) = self.authorise(ticket.credential_id(), &call, &payload, now).await?;
                headers.extend(added);
                version = Some(used);
            }
            let query = call.query_string().map(|query| format!("?{query}")).unwrap_or_default();
            let url = format!("{}{}{query}", self.base, call.path);
            let borrowed: Vec<(&str, String)> = headers.iter().map(|(name, value)| (name.as_str(), value.clone())).collect();
            let answer = https::call(call.method, &url, &borrowed, call.body.as_ref().map(|_| (content_type, payload)), WAIT).await;
            match answer {
                Ok(answer) => {
                    let wait = answer.header("retry-after").and_then(|said| retry_after(said, now));
                    let reply = Reply { status: answer.status.as_u16(), body: answer.body, retry_after: wait };
                    self.answered(&reply, now);
                    if let (Ok(mut state), Some(version)) = (self.state.lock(), version) {
                        state.version_used = Some(version);
                    }
                    Ok(reply)
                }
                Err(said) => {
                    self.unreachable(now);
                    Err(Trouble::Refused(said))
                }
            }
        })
    }

    fn version_used(&self) -> Option<u32> {
        self.state.lock().ok().and_then(|state| state.version_used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wire_is_pointed_at_one_place_and_says_what_it_does_without_saying_what_it_holds() {
        struct Nothing;
        impl Keys for Nothing {
            fn open(&self, _: &str) -> Result<Opened, String> {
                Err("not in this test".into())
            }
        }
        let present = Present::AwsSigV4 { service: "ec2".into(), region: "eu-west-1".into(), access_field: "accessKeyId".into(), secret_field: "secretAccessKey".into() };
        let wire = Keyed::new("https://ec2.eu-west-1.amazonaws.com", "https://ec2.eu-west-1.amazonaws.com", present, Box::new(Nothing), 0).unwrap();
        assert_eq!(wire.presents(), "signs each request with the credential and sends no key");
        assert!(!wire.sends_the_value(), "a signed request carries a signature and not the key that made it");
        assert!(format!("{wire:?}").contains("ec2.eu-west-1.amazonaws.com") && !format!("{wire:?}").contains("secretAccessKey"));

        // The two kinds that do put the value on the request say so, which is what an
        // administrator deciding where a credential may be used needs to know.
        let bearer = Keyed::new("https://api.example", "https://api.example", Present::Bearer { field: "token".into() }, Box::new(Nothing), 0).unwrap();
        assert!(bearer.sends_the_value());
        let minted = Present::ClientCredentials { token_url: "https://login.example/t".into(), client_id: "app".into(), scope: "s".into(), field: "clientSecret".into() };
        let exchanged = Keyed::new("https://api.example", "https://api.example", minted, Box::new(Nothing), 0).unwrap();
        assert!(!exchanged.sends_the_value(), "what travels is the token, and the secret goes only to the sign-in");

        // An address is where something is, not a way into it, and a destination is https.
        let keys = || Box::new(Nothing) as Box<dyn Keys>;
        let bearer = || Present::Bearer { field: "token".into() };
        assert!(Keyed::new("http://api.example", "https://api.example", bearer(), keys(), 0).is_err());
        assert!(Keyed::new("https://api.example?token=abc", "https://api.example", bearer(), keys(), 0).is_err());
        assert!(Keyed::new("https://api.example", "http://api.example", bearer(), keys(), 0).is_err(), "plain http is only ever this computer");
        assert!(Keyed::new("https://api.example", "http://127.0.0.1:8080", bearer(), keys(), 0).is_ok(), "which is what the fixtures in these tests are");
    }

    #[test]
    fn the_azure_storage_signature_is_the_string_microsoft_documents() {
        // A key that is base64 of "a secret nobody reads", so the arithmetic is reproducible here
        // and the test says what it signs rather than what it got.
        let key = "YSBzZWNyZXQgbm9ib2R5IHJlYWRz";
        let call = Call::get("/parking").with("restype", "container").with("comp", "list");
        let headers = vec![("x-ms-date".to_owned(), "Tue, 01 Nov 2022 09:00:00 GMT".to_owned()), ("x-ms-version".to_owned(), AZURE_STORAGE_VERSION.to_owned())];
        let signature = azure_shared_key(key, "acme", &call, &[], &headers).unwrap();

        // The same string, built by hand here, so the test fails if the shape of it changes.
        use base64::Engine;
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let expected_string = format!("GET\n\n\n\n\n\n\n\n\n\n\n\nx-ms-date:Tue, 01 Nov 2022 09:00:00 GMT\nx-ms-version:{AZURE_STORAGE_VERSION}\n/acme/parking\ncomp:list\nrestype:container");
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&base64::engine::general_purpose::STANDARD.decode(key).unwrap()).unwrap();
        mac.update(expected_string.as_bytes());
        assert_eq!(signature, base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes()));

        // A key that is not base64 is refused in words, not with a signature over nothing.
        assert!(azure_shared_key("not base64 !!", "acme", &call, &[], &headers).unwrap_err().say().contains("base64"));
    }

    #[test]
    fn times_are_formatted_the_way_each_signature_wants_them() {
        assert_eq!(amz_date(1_667_293_200), "20221101T090000Z");
        assert_eq!(http_date(1_667_293_200), "Tue, 01 Nov 2022 09:00:00 GMT");
    }

    #[test]
    fn one_element_at_a_time_is_read_out_of_an_xml_answer() {
        let xml = "<DescribeInstancesResponse><reservationSet><item><instancesSet><item><instanceId>i-1</instanceId><instanceType>m5.large</instanceType></item></instancesSet></item><item><instancesSet><item><instanceId>i-2</instanceId></item></instancesSet></item></reservationSet></DescribeInstancesResponse>";
        assert_eq!(xml_text(xml, "instanceId").as_deref(), Some("i-1"));
        assert_eq!(xml_all(xml, "instanceId"), vec!["i-1".to_owned(), "i-2".to_owned()]);
        assert_eq!(xml_text(xml, "nothingHere"), None, "an element that is not there is nothing, never an empty string");
        assert_eq!(xml_text("<Message>Access Denied &amp; logged</Message>", "Message").as_deref(), Some("Access Denied & logged"));
    }
}
