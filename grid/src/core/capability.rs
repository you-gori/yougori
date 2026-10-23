//! Capability tokens: a narrow, short-lived permission to do one thing.
//!
//! A workload never holds a credential or an open-ended session. It holds a token that says which
//! realm, which principal, which device, which workload, what it may touch, and until when. The
//! token is signed with its realm's own key, so a token minted in one realm cannot be read, let
//! alone accepted, by another: the realms hold different keys and the signature simply fails.
//!
//! The holder cannot change a claim without breaking the signature, and the issuer checks every
//! constraint again at the moment it acts, not only when the token was minted.
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;

/// How long after a permission has expired its record is kept.
///
/// An expired permission is refused on its own expiry, so keeping the row buys nothing about
/// authorisation. What it buys is a day in which the record of one still exists while somebody
/// works out what happened, and `forget_expired_capabilities` keeps a row longer than this anyway
/// while the agreement it came from still stands, because that row is the only record that the
/// agreement was already used.
pub const KEEP_EXPIRED: i64 = 24 * 60 * 60;

/// What the token allows. Everything is checked again before the action runs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Claims {
    /// A random identity for this token, so a single-use token cannot be replayed.
    pub id: String,
    pub realm_id: String,
    pub capability: super::realm::Capability,
    pub principal_id: String,
    pub device_id: String,
    /// The piece of work this was minted for; nothing else may present it.
    pub workload_id: String,
    /// What it may act on: a credential, a workspace, a model.
    pub resource_id: String,
    /// Where it may be sent, when the action reaches outside.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,
    /// Which method it may use, when that is meaningful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// Which path it may touch, when that is meaningful.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// The largest body it may carry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maximum_bytes: Option<u64>,
    /// The approval that allowed this, when one was required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_id: Option<String>,
    /// Whether it may be presented more than once before it expires.
    pub single_use: bool,
    pub issued_at: i64,
    pub expires_at: i64,
}

impl Claims {
    /// A token for one action, valid for `seconds`.
    pub fn new(realm_id: &str, capability: super::realm::Capability, principal_id: &str, device_id: &str, workload_id: &str, resource_id: &str, now: i64, seconds: i64) -> Claims {
        Claims {
            id: format!("cap-{}", &crate::token()[..24]),
            realm_id: realm_id.to_owned(),
            capability,
            principal_id: principal_id.to_owned(),
            device_id: device_id.to_owned(),
            workload_id: workload_id.to_owned(),
            resource_id: resource_id.to_owned(),
            destination: None,
            method: None,
            path: None,
            maximum_bytes: None,
            approval_id: None,
            single_use: true,
            issued_at: now,
            expires_at: now + seconds.clamp(1, 24 * 60 * 60),
        }
    }

    /// Narrows the token to one destination, method and path.
    pub fn bound_to(mut self, destination: &str, method: &str, path: &str, maximum_bytes: u64) -> Claims {
        self.destination = Some(destination.to_owned());
        self.method = Some(method.to_ascii_uppercase());
        self.path = Some(path.to_owned());
        self.maximum_bytes = Some(maximum_bytes);
        self
    }
}

/// What the holder is trying to do right now, checked against the claims.
#[derive(Clone, Debug, Default)]
pub struct Attempt<'a> {
    pub realm_id: &'a str,
    pub device_id: &'a str,
    pub workload_id: &'a str,
    pub resource_id: &'a str,
    pub destination: Option<&'a str>,
    pub method: Option<&'a str>,
    pub path: Option<&'a str>,
    pub bytes: Option<u64>,
}

/// Why a token was not accepted. The reasons are for the audit; the caller is told plainly that
/// the token was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Refused {
    Malformed,
    /// The signature does not belong to the realm that is checking it, which is also what
    /// happens when a token from another realm is presented here.
    WrongRealm,
    Expired,
    AlreadyUsed,
    /// A claim and the attempt disagree; the field is named for the audit.
    Mismatch(&'static str),
}

impl Refused {
    pub fn describe(&self) -> String {
        match self {
            Refused::Malformed => "This permission is not readable".into(),
            Refused::WrongRealm => "This permission was not issued by this grid".into(),
            Refused::Expired => "This permission has expired".into(),
            Refused::AlreadyUsed => "This permission was already used".into(),
            Refused::Mismatch(field) => format!("This permission does not allow that {field}"),
        }
    }
}

/// Mints and checks capability tokens for one realm, with its key.
pub struct Authority {
    realm_id: String,
    key: String,
    /// Tokens already presented, kept until they expire so a single-use one cannot be replayed.
    spent: HashMap<String, i64>,
}

impl Authority {
    pub fn new(realm_id: &str, key: &str) -> Authority {
        Authority { realm_id: realm_id.to_owned(), key: key.to_owned(), spent: HashMap::new() }
    }

    fn sign(&self, body: &str) -> String {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(self.key.as_bytes()).expect("HMAC takes any key length");
        mac.update(body.as_bytes());
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    }

    /// The token a holder carries: its claims and a signature over them.
    pub fn mint(&self, claims: &Claims) -> Result<String, String> {
        if claims.realm_id != self.realm_id {
            return Err("A grid only mints permissions for itself".into());
        }
        let body = URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).map_err(|error| error.to_string())?);
        let signature = self.sign(&body);
        Ok(format!("{body}.{signature}"))
    }

    /// Reads a token without accepting it: for showing an admin what a holder carries.
    pub fn peek(token: &str) -> Option<Claims> {
        let body = token.split('.').next()?;
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).ok()?).ok()
    }

    /// Reads a token and proves it is this realm's, without spending it and without looking at
    /// what is being attempted.
    ///
    /// A caller that has to look the claims up before it can decide anything needs this rather
    /// than `peek`, which checks nothing at all. What a token says is attacker-chosen text until
    /// the signature over it has been checked, and some of the places claims are written to, such
    /// as the identifier fields of an audit event, are not filtered the way a free-text reason is.
    pub fn verified(&self, token: &str) -> Result<Claims, Refused> {
        let (body, signature) = token.split_once('.').ok_or(Refused::Malformed)?;
        if body.len() > 8192 || signature.len() > 256 {
            return Err(Refused::Malformed);
        }
        // Constant-time comparison: a wrong signature never says how wrong it was.
        let wanted = self.sign(body);
        if wanted.len() != signature.len() || wanted.bytes().zip(signature.bytes()).fold(0u8, |seen, (a, b)| seen | (a ^ b)) != 0 {
            return Err(Refused::WrongRealm);
        }
        let claims: Claims = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(body).map_err(|_| Refused::Malformed)?).map_err(|_| Refused::Malformed)?;
        if claims.realm_id != self.realm_id {
            return Err(Refused::WrongRealm);
        }
        Ok(claims)
    }

    /// Accepts `token` for `attempt`, or says why not. A single-use token is spent here, so the
    /// same one is refused the second time.
    pub fn accept(&mut self, token: &str, attempt: &Attempt<'_>, now: i64) -> Result<Claims, Refused> {
        let claims = self.verified(token)?;
        if attempt.realm_id != self.realm_id {
            return Err(Refused::WrongRealm);
        }
        if now >= claims.expires_at {
            return Err(Refused::Expired);
        }
        self.spent.retain(|_, expires| *expires > now);
        if claims.single_use && self.spent.contains_key(&claims.id) {
            return Err(Refused::AlreadyUsed);
        }
        if claims.device_id != attempt.device_id {
            return Err(Refused::Mismatch("computer"));
        }
        if claims.workload_id != attempt.workload_id {
            return Err(Refused::Mismatch("piece of work"));
        }
        if claims.resource_id != attempt.resource_id {
            return Err(Refused::Mismatch("resource"));
        }
        if let Some(allowed) = &claims.destination {
            if attempt.destination != Some(allowed.as_str()) {
                return Err(Refused::Mismatch("destination"));
            }
        }
        if let Some(allowed) = &claims.method {
            if attempt.method.map(str::to_ascii_uppercase).as_deref() != Some(allowed.as_str()) {
                return Err(Refused::Mismatch("method"));
            }
        }
        if let Some(allowed) = &claims.path {
            if attempt.path != Some(allowed.as_str()) {
                return Err(Refused::Mismatch("path"));
            }
        }
        if let (Some(limit), Some(size)) = (claims.maximum_bytes, attempt.bytes) {
            if size > limit {
                return Err(Refused::Mismatch("size"));
            }
        }
        if claims.single_use {
            self.spent.insert(claims.id.clone(), claims.expires_at);
        }
        Ok(claims)
    }
}
