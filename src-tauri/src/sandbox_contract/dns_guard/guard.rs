//! The wire layer around V11's guest DNS decision (VM-W08: "Host independently
//! authorizes", acceptance "no external DNS for unauthorized names"; VM §4.2 steps 1–4;
//! VM §2.5: DNS queries are a release channel).
//!
//! V11 owns the decision: [`HostNetwork::guest_dns`] parses the name with V02's one
//! destination parser, picks the profile's grant for it, answers locally whatever needs no
//! query, resolves a granted name only through that grant's own allowed resolver (charged
//! to the route's name budget and the DNS release channel by the V02 broker), checks the
//! grant's perimeter prefixes, and records the validated addresses as the bindings later
//! flows are admitted against. This module adds only the wire format around it:
//!
//! 1. The message is parsed strictly ([`parse_query`]). A refused message gets FORMERR or
//!    NOTIMP, or no response at all ([`QueryProblem::response_code`]); V11 is not asked.
//! 2. The question name becomes text
//!    ([`Question::name_text`](super::query::Question::name_text)); a name the wire form
//!    cannot write as text without a guess is answered as V11 answers a malformed name,
//!    without asking V11. The question type becomes V02's
//!    [`GuestQueryType`](crate::sandbox_contract::destinations::GuestQueryType).
//! 3. [`HostNetwork::guest_dns`] decides, and its [`DnsAnswer`] is encoded with
//!    [`encode_response`]: the transaction id kept, the question echoed exactly.
//!
//! # Response codes
//!
//! Per V11 [`DnsAnswer`] variant ([`response_code`]):
//!
//! - `Addresses`: NOERROR with the addresses; SERVFAIL if their lifetime already ended.
//! - `NoData`: NOERROR without records (NODATA).
//! - `NameNotAuthorized`: NXDOMAIN, since V11 answers it "locally as nonexistent".
//! - `Malformed`: NXDOMAIN, since no destination of that name exists for the sandbox;
//!   FORMERR would blame a message that parsed.
//! - `Unsupported`: NOTIMP, as V02 documents for a query type that is not served.
//! - `Refused`: REFUSED for a policy refusal (authorization, a route budget, the release
//!   channel, address rules, perimeter prefixes); SERVFAIL for a failed or unusable
//!   resolution and for host-side faults ([`refusal_code`]).
//! - An error from `guest_dns` itself: the same refusal mapping; an unknown sandbox is
//!   REFUSED.
//!
//! A strict-mode or offline sandbox has no broader network profile, so V11 never admits
//! one and answers it as an unknown sandbox: REFUSED. The guard adds no rule of its own.
//!
//! # TTL
//!
//! An answer's TTL is its remaining lifetime, `valid_until` less [`HostNetwork::now`], the
//! clock V11 and its broker decided on, in whole seconds rounded down and capped at the
//! profile's longest answer lifetime, so the guest's cached answer never outlasts V11's
//! binding. An answer whose lifetime already ended is not sent (SERVFAIL).
//!
//! Large answers are trimmed to the records that fit in 512 bytes, without the TC bit:
//! the guard serves no DNS over TCP, so TC would send the stub to a listener that does not
//! exist. V11 binds every validated address, sent or not.
//!
//! # Note for the owner: NXDOMAIN or REFUSED for an ungranted name
//!
//! V11 answers an ungranted name as nonexistent, and the guard follows it. For the record,
//! the case for REFUSED:
//!
//! - RFC 1035 §4.1.1 defines REFUSED for a refusal "for policy reasons"; NXDOMAIN states
//!   that the name does not exist in DNS, which is false for most ungranted names;
//! - NXDOMAIN means nothing exists at or below the name (RFC 8020), so a guest-side cache
//!   could deny a granted `api.example.com` after an NXDOMAIN for an ungranted
//!   `example.com` (these responses carry no SOA, so RFC 2308 caches should not keep
//!   them, but not every cache follows that).
//!
//! Against it: on REFUSED, glibc tries the next configured server and, when every server
//! refuses, `getaddrinfo` reports `EAI_AGAIN`, a temporary failure that invites retries;
//! NXDOMAIN ends the lookup with `EAI_NONAME` once the search list is walked. Neither
//! choice causes an external query: V11 asks no resolver for an ungranted name.
//!
//! Likewise, a resolver's NXDOMAIN or NODATA for a granted name reaches the guard inside
//! V11's `Refused`, and is sent as SERVFAIL; passing it on would be truer to the guest.

use std::net::IpAddr;

use super::query::{parse_query, QueryProblem, QueryRefusal};
use super::response::{
    answer_capacity, encode_response, EncodeError, ResponseCode, MAX_TTL_SECONDS,
};
use crate::foundation::ids::{Clock, ExecutionId, MonotonicTime};
use crate::sandbox_contract::destinations::{DestinationRefusal, NameError, Resolver};
use crate::sandbox_contract::netprofile::{DnsAnswer, FlowRefusal, HostNetwork};

/// What the guard did with one message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GuardOutcome {
    /// Nothing was sent: the message had no full header or was a response.
    Dropped(QueryProblem),
    /// The parser refused the message (FORMERR or NOTIMP); V11 was not asked.
    Malformed(QueryProblem),
    /// The question name has a label holding a dot or a non-ASCII byte, so it has no
    /// unambiguous text form; answered as V11 answers a malformed name (NXDOMAIN), without
    /// asking V11.
    UnwritableName(NameError),
    /// V11 decided. `sent` holds the address records in the response and `ttl_seconds`
    /// their TTL; both are empty and zero for an answer without records.
    Decided {
        answer: DnsAnswer,
        sent: Vec<IpAddr>,
        ttl_seconds: u32,
    },
    /// V11 answered with addresses whose lifetime had already ended (SERVFAIL).
    Expired { answer: DnsAnswer },
    /// V11 refused the query itself, such as for a sandbox it never admitted.
    HostRefused(FlowRefusal),
    /// The encoder refused V11's addresses (SERVFAIL); V11 never returns such an answer.
    Unencodable {
        answer: DnsAnswer,
        error: EncodeError,
    },
}

/// The guard's reply to one message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuardReply {
    /// The response code sent, or `None` when nothing is sent.
    pub code: Option<ResponseCode>,
    /// The response for the guest, at most 512 bytes, or `None` to send nothing.
    pub response: Option<Vec<u8>>,
    pub outcome: GuardOutcome,
}

/// The response code for V11's answer (the table in the module docs). An `Addresses`
/// answer is NOERROR here; the guard sends SERVFAIL instead once its lifetime has ended.
pub fn response_code(answer: &DnsAnswer) -> ResponseCode {
    match answer {
        DnsAnswer::Addresses { .. } | DnsAnswer::NoData => ResponseCode::NoError,
        DnsAnswer::NameNotAuthorized | DnsAnswer::Malformed(_) => ResponseCode::NxDomain,
        DnsAnswer::Unsupported(_) => ResponseCode::NotImp,
        DnsAnswer::Refused(refusal) => refusal_code(refusal),
    }
}

/// The response code for a V11 refusal: REFUSED where policy said no and asking again
/// cannot help; SERVFAIL where the resolution failed or its answer was unusable, and for
/// host-side faults. Every variant is listed, so a new one must be placed deliberately.
pub const fn refusal_code(refusal: &FlowRefusal) -> ResponseCode {
    use FlowRefusal as Refusal;
    match refusal {
        Refusal::Destination(refusal) => destination_code(refusal),
        Refusal::UnknownSandbox { .. }
        | Refusal::SpoofedSource { .. }
        | Refusal::FamilyMismatch
        | Refusal::NoIpv6Identity
        | Refusal::InvalidPort
        | Refusal::HostService { .. }
        | Refusal::OwnAddress
        | Refusal::UnassignedSandboxAddress { .. }
        | Refusal::Address(_)
        | Refusal::Authorization(_)
        | Refusal::OutsidePerimeterPrefixes { .. }
        | Refusal::TransportNotGranted { .. }
        | Refusal::Connection(_)
        | Refusal::Ingress(_)
        | Refusal::ConcurrentFlowLimit { .. }
        | Refusal::NewFlowRate { .. }
        | Refusal::Budget(_)
        | Refusal::Release(_)
        | Refusal::Name(_)
        | Refusal::IdentityHostOwned { .. } => ResponseCode::Refused,
        Refusal::AlreadyEstablished { .. }
        | Refusal::NotEstablished
        | Refusal::UnsolicitedInbound
        | Refusal::BindingExpired { .. }
        | Refusal::Nat(_)
        | Refusal::Settle(_)
        | Refusal::ResolverUnavailable { .. }
        | Refusal::WrongFlowKind
        | Refusal::FlowIdsExhausted => ResponseCode::ServFail,
    }
}

/// The response code for a V02 broker refusal inside a V11 refusal.
const fn destination_code(refusal: &DestinationRefusal) -> ResponseCode {
    use DestinationRefusal as Refusal;
    match refusal {
        Refusal::Authorization(_)
        | Refusal::ResolutionForbidden
        | Refusal::ResolverNotAllowed { .. }
        | Refusal::Ipv6NotGranted
        | Refusal::Budget(_)
        | Refusal::Release(_)
        | Refusal::Address(_)
        | Refusal::Synthetic(_)
        | Refusal::Redirect(_)
        | Refusal::RedirectsDisabled
        | Refusal::RedirectLeavesRoute { .. } => ResponseCode::Refused,
        Refusal::ResolverFailed(_)
        | Refusal::AnswerForOtherName { .. }
        | Refusal::WrongFamily { .. }
        | Refusal::AliasChainTooLong { .. }
        | Refusal::EmptyAnswer
        | Refusal::Stale { .. }
        | Refusal::Expired
        | Refusal::Settle(_)
        | Refusal::NotNewer
        | Refusal::UnknownRoute { .. }
        | Refusal::EndpointNotResolved
        | Refusal::NotAnEndpoint
        | Refusal::AddressNotValidated { .. } => ResponseCode::ServFail,
    }
}

/// Handles one DNS message from `sandbox`'s guest: parses it, lets
/// [`HostNetwork::guest_dns`] decide with `resolvers` (V11 picks the grant's own resolver
/// by id; others are never asked), and encodes the decision. Never panics.
pub fn handle_query<C: Clock + Clone>(
    host: &mut HostNetwork<C>,
    sandbox: &ExecutionId,
    resolvers: &[&dyn Resolver],
    message: &[u8],
) -> GuardReply {
    let query = match parse_query(message) {
        Ok(query) => query,
        Err(refusal) => return malformed(refusal),
    };
    let header = query.header();
    let question = query.question();
    let reply = |code: ResponseCode, outcome: GuardOutcome| {
        let response = encode_response(&header, Some(question), code, &[], 0).ok();
        GuardReply {
            code: response.as_ref().map(|_| code),
            response,
            outcome,
        }
    };
    let name = match question.name_text() {
        Ok(name) => name,
        Err(error) => {
            return reply(ResponseCode::NxDomain, GuardOutcome::UnwritableName(error));
        }
    };
    let answer = match host.guest_dns(sandbox, &name, question.query_type(), resolvers) {
        Ok(answer) => answer,
        Err(refusal) => return reply(refusal_code(&refusal), GuardOutcome::HostRefused(refusal)),
    };
    let DnsAnswer::Addresses {
        addresses,
        valid_until,
        ..
    } = &answer
    else {
        return reply(
            response_code(&answer),
            GuardOutcome::Decided {
                answer,
                sent: Vec::new(),
                ttl_seconds: 0,
            },
        );
    };
    let cap = host.profile(sandbox).map_or(MAX_TTL_SECONDS, |profile| {
        u32::try_from(profile.document().max_answer_ttl_seconds.get())
            .map_or(MAX_TTL_SECONDS, |seconds| seconds.min(MAX_TTL_SECONDS))
    });
    let Some(ttl_seconds) = ttl_seconds(*valid_until, host.now(), cap) else {
        return reply(ResponseCode::ServFail, GuardOutcome::Expired { answer });
    };
    let sent: Vec<IpAddr> = addresses
        .iter()
        .copied()
        .take(answer_capacity(question))
        .collect();
    match encode_response(
        &header,
        Some(question),
        ResponseCode::NoError,
        &sent,
        ttl_seconds,
    ) {
        Ok(response) => GuardReply {
            code: Some(ResponseCode::NoError),
            response: Some(response),
            outcome: GuardOutcome::Decided {
                answer,
                sent,
                ttl_seconds,
            },
        },
        Err(error) => reply(
            ResponseCode::ServFail,
            GuardOutcome::Unencodable { answer, error },
        ),
    }
}

/// The TTL of an answer valid until `valid_until`: the remaining lifetime at `now` in whole
/// seconds, rounded down and capped at `cap`; `None` once it has ended.
fn ttl_seconds(valid_until: MonotonicTime, now: MonotonicTime, cap: u32) -> Option<u32> {
    let remaining = valid_until.checked_duration_since(now)?;
    if remaining.is_zero() {
        return None;
    }
    Some(u32::try_from(remaining.as_secs()).map_or(cap, |seconds| seconds.min(cap)))
}

/// The reply to a message the parser refused.
fn malformed(refusal: QueryRefusal) -> GuardReply {
    let problem = refusal.problem();
    let response = match (problem.response_code(), refusal.header()) {
        (Some(code), Some(header)) => encode_response(&header, refusal.question(), code, &[], 0)
            .ok()
            .map(|response| (code, response)),
        _ => None,
    };
    match response {
        Some((code, response)) => GuardReply {
            code: Some(code),
            response: Some(response),
            outcome: GuardOutcome::Malformed(problem),
        },
        None => GuardReply {
            code: None,
            response: None,
            outcome: GuardOutcome::Dropped(problem),
        },
    }
}
