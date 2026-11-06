//! Strict, bounded reading of what runpodctl prints (VM-W39; VM part §6.3 step 5 and
//! VM-W31: uncertain outcomes are recorded as uncertain, never guessed).
//!
//! The output reaching here is already cut at its bound by the port; anything over the
//! bound is refused before parsing. JSON is read with `serde_json` (its nesting limit
//! applies). runpodctl's own JSON carries many fields this transport does not use and may
//! gain more, so unknown fields are ignored; what is used must be present with exactly the
//! expected type and a value from the expected set, or the answer is refused.
//!
//! Field names, as neocloud's reviewed code reads them (`neocloud/runpod.rs`):
//!
//! - `pod create`: `id`, or `pod.id`;
//! - `pod list --all`: a list of objects with `id`, `name` (text or null) and
//!   `desiredStatus`;
//! - `pod get`: `id`, `name`, `desiredStatus`, `gpuTypeId`, `gpuCount`,
//!   `machine.dataCenterId`, and `ssh.ip` with `ssh.port`;
//! - `ssh list-keys`: `keys`, a list of objects with `key`;
//! - any failure: `{"error": "<message>"}` on stdout or stderr, or stderr's first or
//!   last line.
//!
//! None of these was checked against a live runpodctl here (E01/E05). A release that
//! names them otherwise makes every answer unreadable, so every outcome is uncertain and
//! nothing is created, found or confirmed absent on a guess.
//!
//! Failure messages are recognised whole, never by substring, after trimming, dropping a
//! leading `Error:` and a final full stop, in any letter case. Two kinds are recognised:
//! runpodctl refusing its own arguments before sending anything (Cobra's `unknown flag:`,
//! `unknown shorthand flag:`, `unknown command`, `required flag(s)` and `invalid
//! argument` starts), and the provider refusals in [`PROVIDER_REFUSALS`]. Their wording is
//! from RunPod's API as remembered and neocloud's messages, not from a live check; wording
//! that differs is unrecognised, which is uncertain, never "not created".

use std::net::IpAddr;

use serde::Serialize;
use serde_json::{Map, Value};

use super::values::{GpuTypeId, PodId, PodStatus};
use crate::sandbox_contract::destinations::{
    classify, AddressRefused, AddressRule, Authority, DestinationHost, DestinationPort,
    HostAddressState,
};
use crate::sandbox_contract::remote::{ProviderError, RegionName};
use crate::sandbox_contract::remote_ssh::SshOutput;

/// Provider refusals that say nothing was done, in the normalised form compared.
pub const PROVIDER_REFUSALS: &[(&str, ProviderError)] = &[
    (
        "there are no longer any instances available with the requested specifications. \
         please refresh and try again",
        ProviderError::CapacityUnavailable,
    ),
    (
        "there are no longer any instances available with the requested specifications",
        ProviderError::CapacityUnavailable,
    ),
    (
        "there are no longer any instances available with enough disk space",
        ProviderError::CapacityUnavailable,
    ),
    ("unauthorized", ProviderError::Unauthorized),
    ("401 unauthorized", ProviderError::Unauthorized),
    ("invalid api key", ProviderError::Unauthorized),
];

/// How runpodctl starts a refusal of its own arguments, in the normalised form.
const LOCAL_REFUSAL_STARTS: &[&str] = &[
    "unknown flag: ",
    "unknown shorthand flag: ",
    "unknown command ",
    "required flag(s) ",
    "invalid argument ",
];

/// Why an answer was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ParseProblem {
    /// Not one UTF-8 JSON value.
    NotJson,
    NotAnObject,
    NotAList,
    Missing {
        field: &'static str,
    },
    WrongType {
        field: &'static str,
    },
    BadPodId,
    BadRegion,
    BadGpuType,
    BadGpuCount,
    /// A `desiredStatus` outside RunPod's set, where the answer depends on it.
    UnknownStatus,
    /// An SSH address that is not one IP address in its canonical form, or port 0.
    BadAddress,
    /// The same pod id is listed twice.
    DuplicatePod,
    /// `pod get` answered about another pod than the one asked for.
    OtherPod,
    /// The pod does not carry the attempt's key in its name.
    NameWithoutKey,
}

/// What a failure message was recognised as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recognised {
    /// runpodctl refused its own arguments; nothing was sent.
    LocalRefusal,
    /// The provider refused; nothing was done.
    Provider(ProviderError),
}

/// One pod of a listing. `status` is `None` for a status outside RunPod's set, which
/// matters only for a pod the caller is looking for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ListedPod {
    pub id: PodId,
    pub name: Option<String>,
    pub status: Option<PodStatus>,
}

/// One pod as `pod get` reports it.
#[derive(Clone, Debug, PartialEq)]
pub struct PodDetail {
    pub id: PodId,
    pub name: Option<String>,
    pub status: PodStatus,
    value: Map<String, Value>,
}

/// What `pod get` says was delivered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Delivered {
    pub region: RegionName,
    pub gpu: GpuTypeId,
    pub gpu_count: u32,
}

/// Where a pod takes SSH, as `pod get` reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SshAddress {
    /// No address yet.
    None,
    /// A public address and port.
    Public(Authority),
    /// An address the destination rules refuse, such as loopback or link-local.
    Refused(AddressRefused),
}

fn json(stdout: &[u8]) -> Result<Value, ParseProblem> {
    serde_json::from_slice(stdout).map_err(|_| ParseProblem::NotJson)
}

fn object(value: Value) -> Result<Map<String, Value>, ParseProblem> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(ParseProblem::NotAnObject),
    }
}

fn text<'a>(map: &'a Map<String, Value>, field: &'static str) -> Result<&'a str, ParseProblem> {
    match map.get(field) {
        Some(Value::String(text)) => Ok(text),
        Some(_) => Err(ParseProblem::WrongType { field }),
        None => Err(ParseProblem::Missing { field }),
    }
}

/// A text field that may be null or absent.
fn optional_text(
    map: &Map<String, Value>,
    field: &'static str,
) -> Result<Option<String>, ParseProblem> {
    match map.get(field) {
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(ParseProblem::WrongType { field }),
    }
}

fn pod_id(map: &Map<String, Value>) -> Result<PodId, ParseProblem> {
    PodId::new(text(map, "id")?).map_err(|_| ParseProblem::BadPodId)
}

/// The pod id `pod create` answered with.
pub fn created_pod(stdout: &[u8]) -> Result<PodId, ParseProblem> {
    let map = object(json(stdout)?)?;
    match map.get("id") {
        Some(_) => pod_id(&map),
        None => match map.get("pod") {
            Some(Value::Object(pod)) => pod_id(pod),
            Some(_) => Err(ParseProblem::WrongType { field: "pod" }),
            None => Err(ParseProblem::Missing { field: "id" }),
        },
    }
}

/// Every pod `pod list --all` listed. Any row not of the expected shape refuses the
/// whole listing, since it could be the pod looked for.
pub fn pod_listing(stdout: &[u8]) -> Result<Vec<ListedPod>, ParseProblem> {
    let Value::Array(rows) = json(stdout)? else {
        return Err(ParseProblem::NotAList);
    };
    let mut pods: Vec<ListedPod> = Vec::with_capacity(rows.len());
    for row in rows {
        let map = object(row)?;
        let id = pod_id(&map)?;
        if pods.iter().any(|pod| pod.id == id) {
            return Err(ParseProblem::DuplicatePod);
        }
        let name = optional_text(&map, "name")?;
        let status = PodStatus::parse(text(&map, "desiredStatus")?);
        pods.push(ListedPod { id, name, status });
    }
    Ok(pods)
}

/// What `pod get` reported about `expected`.
pub fn pod_detail(stdout: &[u8], expected: &PodId) -> Result<PodDetail, ParseProblem> {
    let map = object(json(stdout)?)?;
    let id = pod_id(&map)?;
    if id != *expected {
        return Err(ParseProblem::OtherPod);
    }
    let name = optional_text(&map, "name")?;
    let status =
        PodStatus::parse(text(&map, "desiredStatus")?).ok_or(ParseProblem::UnknownStatus)?;
    Ok(PodDetail {
        id,
        name,
        status,
        value: map,
    })
}

impl PodDetail {
    /// The data center, GPU type and GPU count the pod runs on.
    pub fn delivered(&self) -> Result<Delivered, ParseProblem> {
        let machine = match self.value.get("machine") {
            Some(Value::Object(machine)) => machine,
            Some(_) => return Err(ParseProblem::WrongType { field: "machine" }),
            None => return Err(ParseProblem::Missing { field: "machine" }),
        };
        let region =
            RegionName::new(text(machine, "dataCenterId")?).map_err(|_| ParseProblem::BadRegion)?;
        let gpu = GpuTypeId::new(text(&self.value, "gpuTypeId")?)
            .map_err(|_| ParseProblem::BadGpuType)?;
        let gpu_count = match self.value.get("gpuCount") {
            Some(Value::Number(number)) => number
                .as_u64()
                .and_then(|count| u32::try_from(count).ok())
                .ok_or(ParseProblem::BadGpuCount)?,
            Some(_) => return Err(ParseProblem::WrongType { field: "gpuCount" }),
            None => return Err(ParseProblem::Missing { field: "gpuCount" }),
        };
        Ok(Delivered {
            region,
            gpu,
            gpu_count,
        })
    }

    /// The pod's SSH address, judged by the destination rules for an address a provider
    /// reports (V02's [`AddressRule::ResolvedName`]: public only) against `host`'s own
    /// addresses.
    pub fn ssh(&self, host: &HostAddressState) -> Result<SshAddress, ParseProblem> {
        let ssh = match self.value.get("ssh") {
            Some(Value::Object(ssh)) => ssh,
            Some(Value::Null) | None => return Ok(SshAddress::None),
            Some(_) => return Err(ParseProblem::WrongType { field: "ssh" }),
        };
        let ip = match ssh.get("ip") {
            Some(Value::String(ip)) if ip.is_empty() => return Ok(SshAddress::None),
            Some(Value::String(ip)) => ip,
            Some(Value::Null) | None => return Ok(SshAddress::None),
            Some(_) => return Err(ParseProblem::WrongType { field: "ssh.ip" }),
        };
        let address: IpAddr = ip.parse().map_err(|_| ParseProblem::BadAddress)?;
        if address.to_string() != *ip {
            return Err(ParseProblem::BadAddress);
        }
        let port = match ssh.get("port") {
            Some(Value::Number(number)) => number
                .as_u64()
                .and_then(|port| u16::try_from(port).ok())
                .and_then(|port| DestinationPort::new(port).ok())
                .ok_or(ParseProblem::BadAddress)?,
            Some(_) => return Err(ParseProblem::WrongType { field: "ssh.port" }),
            None => return Err(ParseProblem::Missing { field: "ssh.port" }),
        };
        if let Err(refusal) = AddressRule::ResolvedName.check(classify(address, host)) {
            return Ok(SshAddress::Refused(refusal));
        }
        Ok(SshAddress::Public(Authority {
            host: DestinationHost::Address(address),
            port,
        }))
    }
}

/// The base64 body (the second field) of every key `ssh list-keys` listed.
pub fn account_keys(stdout: &[u8]) -> Result<Vec<String>, ParseProblem> {
    let map = object(json(stdout)?)?;
    let rows = match map.get("keys") {
        Some(Value::Array(rows)) => rows,
        Some(_) => return Err(ParseProblem::WrongType { field: "keys" }),
        None => return Err(ParseProblem::Missing { field: "keys" }),
    };
    let mut bodies = Vec::with_capacity(rows.len());
    for row in rows {
        let Value::Object(row) = row else {
            return Err(ParseProblem::NotAnObject);
        };
        let line = text(row, "key")?;
        bodies.push(key_body(line).to_owned());
    }
    Ok(bodies)
}

/// The base64 field of an `authorized_keys` line, or "" when it has none.
pub fn key_body(line: &str) -> &str {
    line.split_whitespace().nth(1).unwrap_or_default()
}

/// A message trimmed, without a leading `Error:` or a final full stop, in lowercase.
fn normalise(message: &str) -> String {
    let message = message.trim();
    let message = match message.get(..6) {
        Some(start) if start.eq_ignore_ascii_case("error:") => message.get(6..).unwrap_or(""),
        _ => message,
    };
    let message = message.trim();
    let message = message.strip_suffix('.').unwrap_or(message);
    message.trim().to_ascii_lowercase()
}

/// The `error` text of a `{"error": "<message>"}` answer, normalised.
pub fn error_object(stream: &[u8]) -> Option<String> {
    match serde_json::from_slice::<Value>(stream) {
        Ok(Value::Object(map)) => match map.get("error") {
            Some(Value::String(message)) if !message.trim().is_empty() => Some(normalise(message)),
            _ => None,
        },
        _ => None,
    }
}

/// The failure messages of a call, normalised, in the order they are judged: an error
/// object on stdout, one on stderr, then stderr's first and last non-empty lines (Cobra
/// prints its own error first and usage after it). Empty when there is none or stderr is
/// not UTF-8.
pub fn failure_messages(output: &SshOutput) -> Vec<String> {
    let mut messages: Vec<String> = error_object(&output.stdout)
        .into_iter()
        .chain(error_object(&output.stderr))
        .collect();
    if let Ok(stderr) = std::str::from_utf8(&output.stderr) {
        let mut lines = stderr.lines().filter(|line| !line.trim().is_empty());
        if let Some(first) = lines.next() {
            messages.push(normalise(first));
        }
        if let Some(last) = lines.next_back() {
            messages.push(normalise(last));
        }
    }
    messages
}

/// What the first recognised message of `messages` is, if any is.
pub fn recognise_any(messages: &[String]) -> Option<Recognised> {
    messages.iter().find_map(|message| recognise(message))
}

/// What a normalised failure message is, if it is recognised.
pub fn recognise(message: &str) -> Option<Recognised> {
    if LOCAL_REFUSAL_STARTS
        .iter()
        .any(|start| message.starts_with(start))
    {
        return Some(Recognised::LocalRefusal);
    }
    PROVIDER_REFUSALS
        .iter()
        .find(|(known, _)| *known == message)
        .map(|(_, error)| Recognised::Provider(*error))
}
