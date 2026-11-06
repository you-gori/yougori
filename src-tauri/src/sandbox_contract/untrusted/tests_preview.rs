//! Preview origin policy tests: VM §4.7 lines 2034 and 2038, VM-CP-28 (preview part),
//! VM-P03, VM-P33 (preview release path) and VM-P35.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use super::preview::{
    check_preview, derive_preview_origin, site_relation, FrameAncestors, HeaderLine,
    HostApplicationOrigin, OriginError, PreviewContext, PreviewDomain, PreviewOrigin,
    PreviewPolicy, PreviewSource, PreviewSubject, PreviewSuffix, PreviewViolation, SiteRelation,
    SuffixListing,
};
use crate::foundation::ids::{ExecutionId, MonotonicTime, SandboxBootGeneration};
use crate::foundation::transfer::GeneralReleaseBudget;
use crate::sandbox_contract::destinations::{
    Audience, AuthenticationMode, ChannelPolicy, DestinationPort, InFlightAllowance, InboundCaller,
    IngressTable, NetworkMode, PrincipalId, PublicationId, PublicationRequest, ReleaseAccount,
    ReleaseChannel, ReleaseTrustClass, ServiceIdentity,
};

const NOW: MonotonicTime = MonotonicTime::from_nanos(1_000_000_000);
const GENERATION: SandboxBootGeneration = SandboxBootGeneration::FIRST;

fn at_seconds(seconds: u64) -> MonotonicTime {
    NOW.saturating_add(Duration::from_secs(seconds))
}

fn table(sandbox: &str) -> IngressTable {
    IngressTable::new(
        ExecutionId::new(sandbox).unwrap(),
        NetworkMode::DeclaredTransport,
        Duration::from_secs(3600),
    )
}

fn publish(table: &mut IngressTable, service: &str, audience: Audience) -> PublicationId {
    let authentication = match audience {
        Audience::Public => AuthenticationMode::None,
        Audience::Private { .. } => AuthenticationMode::PlatformSession,
    };
    table
        .publish(
            PublicationRequest {
                service: ServiceIdentity::new(service).unwrap(),
                port: DestinationPort::new(8080).unwrap(),
                audience,
                authentication,
                expires_at: at_seconds(600),
            },
            NOW,
        )
        .unwrap()
}

fn private_to(names: &[&str]) -> Audience {
    Audience::Private {
        principals: names
            .iter()
            .map(|name| PrincipalId::new(*name).unwrap())
            .collect(),
    }
}

fn local_domain() -> PreviewDomain {
    PreviewDomain::new("localhost", SuffixListing::NotListed).unwrap()
}

fn tauri() -> HostApplicationOrigin {
    HostApplicationOrigin::parse("tauri://localhost").unwrap()
}

struct Fixture {
    table: IngressTable,
    id: PublicationId,
    host: HostApplicationOrigin,
    domain: PreviewDomain,
}

impl Fixture {
    fn new(audience: Audience) -> Self {
        let mut table = table("sbx-1");
        let id = publish(&mut table, "web", audience);
        Self {
            table,
            id,
            host: tauri(),
            domain: local_domain(),
        }
    }

    fn policy(&self) -> PreviewPolicy {
        PreviewPolicy::for_publication(
            self.table.publication(self.id).unwrap(),
            GENERATION,
            &self.domain,
            &self.host,
            FrameAncestors::None,
        )
    }

    fn check(&self, policy: &PreviewPolicy) -> Vec<PreviewViolation> {
        self.check_with(policy, &[])
    }

    fn check_with(
        &self,
        policy: &PreviewPolicy,
        others: &[PreviewOrigin],
    ) -> Vec<PreviewViolation> {
        let context = PreviewContext {
            table: &self.table,
            generation: GENERATION,
            host: &self.host,
            domain: &self.domain,
            other_previews: others,
            now: NOW,
        };
        match check_preview(policy, &context) {
            Ok(()) => Vec::new(),
            Err(refusal) => refusal.violations,
        }
    }
}

#[test]
fn the_strict_policy_record_passes_its_own_check() {
    for audience in [Audience::Public, private_to(&["alice"])] {
        let fixture = Fixture::new(audience);
        let policy = fixture.policy();
        assert_eq!(fixture.check(&policy), Vec::new());
        assert_eq!(policy.source, PreviewSource::GuestService);
        assert!(
            !policy.host_state.cookies && !policy.host_state.session && !policy.host_state.storage
        );
        assert!(!policy.file_access.file_urls && policy.file_access.host_paths.is_empty());
        assert!(!policy.forwarding.forward_credentials);
        assert!(policy.origin.serialized().starts_with("https://p"));
        assert!(policy.origin.host().ends_with(".localhost"));
        let csp = &policy.response_headers[0];
        assert_eq!(csp.name, "Content-Security-Policy");
        assert_eq!(
            csp.value,
            "sandbox allow-scripts allow-forms; frame-ancestors 'none'"
        );
    }
}

#[test]
fn origins_are_unique_per_publication_generation_and_sandbox_and_deterministic() {
    let domain = local_domain();
    let mut first = table("sbx-1");
    let web = publish(&mut first, "web", Audience::Public);
    let api = publish(&mut first, "api", Audience::Public);
    let mut second = table("sbx-2");
    let other = publish(&mut second, "web", Audience::Public);
    let subject = |table: &IngressTable, id, generation| {
        PreviewSubject::of(table.publication(id).unwrap(), generation)
    };
    let next = GENERATION.next().unwrap();
    let origins: BTreeSet<PreviewOrigin> = [
        subject(&first, web, GENERATION),
        subject(&first, api, GENERATION),
        subject(&first, web, next),
        subject(&second, other, GENERATION),
    ]
    .iter()
    .map(|subject| derive_preview_origin(subject, &domain))
    .collect();
    assert_eq!(origins.len(), 4);
    assert_eq!(
        derive_preview_origin(&subject(&first, web, GENERATION), &domain),
        derive_preview_origin(&subject(&first, web, GENERATION), &domain)
    );
    // Withdrawing and publishing again at the same instant still gives a new origin.
    first.withdraw(web).unwrap();
    let again = publish(&mut first, "web", Audience::Public);
    assert_ne!(
        derive_preview_origin(&subject(&first, again, GENERATION), &domain),
        derive_preview_origin(&subject(&first, web, GENERATION), &domain)
    );
}

#[test]
fn a_preview_is_never_same_site_with_the_host_application() {
    let mut fixture = Fixture::new(Audience::Public);
    for host in [
        "tauri://localhost",
        "http://tauri.localhost",
        "https://app.yougori.com",
    ] {
        fixture.host = HostApplicationOrigin::parse(host).unwrap();
        let policy = fixture.policy();
        assert_eq!(fixture.check(&policy), Vec::new(), "{host}");
    }
    fixture.host = HostApplicationOrigin::parse("https://app.yougori.com").unwrap();
    fixture.domain =
        PreviewDomain::new("previews.yougori.com", SuffixListing::DeclaredPublicSuffix).unwrap();
    let violations = fixture.check(&fixture.policy());
    assert!(
        violations.contains(&PreviewViolation::SameSiteAsHostApplication {
            common_suffix: Some("yougori.com".to_owned())
        })
    );
    // A wrong listing declaration cannot put the host application under the suffix.
    fixture.domain =
        PreviewDomain::new("yougori.com", SuffixListing::DeclaredPublicSuffix).unwrap();
    let violations = fixture.check(&fixture.policy());
    assert!(violations.contains(&PreviewViolation::HostApplicationUnderPreviewSuffix));
    fixture.host = HostApplicationOrigin::parse("https://yougori.com").unwrap();
    assert!(fixture
        .check(&fixture.policy())
        .contains(&PreviewViolation::HostApplicationUnderPreviewSuffix));
}

#[test]
fn previews_of_other_sandboxes_are_cross_site_only_below_a_public_suffix() {
    let mut fixture = Fixture::new(Audience::Public);
    let mut neighbour = table("sbx-2");
    let id = publish(&mut neighbour, "web", Audience::Public);
    let neighbour_subject = PreviewSubject::of(neighbour.publication(id).unwrap(), GENERATION);
    let others = [derive_preview_origin(&neighbour_subject, &fixture.domain)];
    assert_eq!(fixture.check_with(&fixture.policy(), &others), Vec::new());

    fixture.domain = PreviewDomain::new("previews.example.net", SuffixListing::NotListed).unwrap();
    let others = [derive_preview_origin(&neighbour_subject, &fixture.domain)];
    let violations = fixture.check_with(&fixture.policy(), &others);
    assert!(violations.contains(&PreviewViolation::SuffixNotPublic));
    assert!(violations.iter().any(|violation| matches!(
        violation,
        PreviewViolation::SameSiteAsOtherPreview { common_suffix, .. }
            if common_suffix == "previews.example.net"
    )));

    fixture.domain =
        PreviewDomain::new("previews.example.net", SuffixListing::DeclaredPublicSuffix).unwrap();
    let others = [derive_preview_origin(&neighbour_subject, &fixture.domain)];
    assert_eq!(fixture.check_with(&fixture.policy(), &others), Vec::new());
}

#[test]
fn an_origin_held_by_another_preview_is_refused() {
    let fixture = Fixture::new(Audience::Public);
    let policy = fixture.policy();
    let violations = fixture.check_with(&policy, std::slice::from_ref(&policy.origin));
    assert_eq!(violations, vec![PreviewViolation::OriginCollision]);
}

#[test]
fn host_state_file_access_and_non_guest_sources_are_refused() {
    let fixture = Fixture::new(Audience::Public);
    let mut policy = fixture.policy();
    policy.host_state.cookies = true;
    policy.host_state.session = true;
    policy.host_state.storage = true;
    policy.file_access.file_urls = true;
    policy.file_access.host_paths = vec!["C:/Users/Argon/.ssh".to_owned()];
    policy.source = PreviewSource::HostPath {
        path: "/home/user".to_owned(),
    };
    assert_eq!(
        fixture.check(&policy),
        vec![
            PreviewViolation::SourceNotGuestService,
            PreviewViolation::FileUrlAccess,
            PreviewViolation::HostPathAccess { paths: 1 },
            PreviewViolation::HostCookies,
            PreviewViolation::HostSession,
            PreviewViolation::HostStorage,
        ]
    );
    policy = fixture.policy();
    policy.source = PreviewSource::FileUrl {
        url: "file:///etc/passwd".to_owned(),
    };
    assert_eq!(
        fixture.check(&policy),
        vec![PreviewViolation::SourceNotGuestService]
    );
}

#[test]
fn credentials_are_never_forwarded_to_the_guest() {
    let fixture = Fixture::new(private_to(&["alice"]));
    let mut policy = fixture.policy();
    policy.forwarding.forward_credentials = true;
    policy.forwarding.stripped_request_headers.remove("cookie");
    assert_eq!(
        fixture.check(&policy),
        vec![
            PreviewViolation::CredentialForwarding,
            PreviewViolation::CredentialHeaderNotStripped { header: "cookie" },
        ]
    );
}

#[test]
fn weakened_or_missing_response_headers_are_refused() {
    let fixture = Fixture::new(Audience::Public);
    let set_csp = |value: &str| {
        let mut policy = fixture.policy();
        policy.response_headers[0].value = value.to_owned();
        fixture.check(&policy)
    };
    assert_eq!(
        set_csp("frame-ancestors 'none'"),
        vec![PreviewViolation::SandboxDirectiveMissing]
    );
    for token in [
        "allow-same-origin",
        "allow-top-navigation",
        "allow-top-navigation-by-user-activation",
        "allow-popups-to-escape-sandbox",
        "allow-downloads",
        "allow-storage-access-by-user-activation",
    ] {
        assert_eq!(
            set_csp(&format!(
                "sandbox allow-scripts {token}; frame-ancestors 'none'"
            )),
            vec![PreviewViolation::SandboxTokenRefused {
                token: token.to_owned()
            }]
        );
    }
    assert_eq!(
        set_csp("sandbox"),
        vec![PreviewViolation::FrameAncestorsMissing]
    );
    for value in [
        "*",
        "https://evil.example",
        "'self'",
        "'none' https://evil.example",
    ] {
        assert_eq!(
            set_csp(&format!("sandbox; frame-ancestors {value}")),
            vec![PreviewViolation::FrameAncestorsTooBroad {
                value: value.to_owned()
            }]
        );
    }
    assert_eq!(
        set_csp("sandbox; sandbox allow-same-origin; frame-ancestors 'none'"),
        vec![PreviewViolation::CspDirectiveDuplicated {
            directive: "sandbox".to_owned()
        }]
    );

    let mut policy = fixture.policy();
    policy
        .response_headers
        .retain(|line| line.name != "Content-Security-Policy");
    assert_eq!(
        fixture.check(&policy),
        vec![PreviewViolation::HeaderMissing {
            name: "content-security-policy"
        }]
    );
    let mut policy = fixture.policy();
    policy.response_headers.push(HeaderLine {
        name: "content-security-policy".to_owned(),
        value: "sandbox allow-same-origin".to_owned(),
    });
    assert!(fixture
        .check(&policy)
        .contains(&PreviewViolation::HeaderDuplicated {
            name: "content-security-policy".to_owned()
        }));
    let mut policy = fixture.policy();
    for line in &mut policy.response_headers {
        match line.name.as_str() {
            "Cross-Origin-Opener-Policy" => line.value = "unsafe-none".to_owned(),
            "Referrer-Policy" => line.value = "unsafe-url".to_owned(),
            "Permissions-Policy" => line.value = "camera=()".to_owned(),
            _ => {}
        }
    }
    policy
        .response_headers
        .retain(|line| line.name != "Cache-Control");
    let violations = fixture.check(&policy);
    assert!(violations.contains(&PreviewViolation::HeaderValueWrong {
        name: "cross-origin-opener-policy",
        required: "same-origin"
    }));
    assert!(violations.contains(&PreviewViolation::HeaderValueWrong {
        name: "referrer-policy",
        required: "no-referrer"
    }));
    assert!(violations.contains(&PreviewViolation::HeaderMissing {
        name: "cache-control"
    }));
    assert!(violations.contains(&PreviewViolation::PermissionNotDenied {
        feature: "clipboard-read"
    }));
    assert!(violations.contains(&PreviewViolation::PermissionNotDenied {
        feature: "clipboard-write"
    }));
    assert!(!violations.contains(&PreviewViolation::PermissionNotDenied { feature: "camera" }));
}

#[test]
fn framing_by_the_host_application_alone_is_accepted() {
    let fixture = Fixture::new(Audience::Public);
    let policy = PreviewPolicy::for_publication(
        fixture.table.publication(fixture.id).unwrap(),
        GENERATION,
        &fixture.domain,
        &fixture.host,
        FrameAncestors::HostApplication,
    );
    assert!(policy.response_headers[0]
        .value
        .ends_with("frame-ancestors tauri://localhost"));
    assert_eq!(fixture.check(&policy), Vec::new());
}

#[test]
fn the_audience_is_shown_exactly_as_v02_records_it() {
    let public = Fixture::new(Audience::Public);
    let policy = public.policy();
    assert_eq!(
        policy.audience_label(),
        "public: anyone who has the address"
    );
    let mut relabelled = policy.clone();
    relabelled.audience = private_to(&["alice"]);
    relabelled.authentication = AuthenticationMode::PlatformSession;
    assert_eq!(
        public.check(&relabelled),
        vec![
            PreviewViolation::AudienceRelabelled {
                recorded_public: true,
                shown_public: false
            },
            PreviewViolation::AuthenticationChanged {
                recorded: AuthenticationMode::None,
                shown: AuthenticationMode::PlatformSession
            },
        ]
    );

    let private = Fixture::new(private_to(&["alice", "bob"]));
    let policy = private.policy();
    assert_eq!(
        policy.audience_label(),
        "private: 2 named principal(s), PlatformSession authentication required"
    );
    let mut relabelled = policy.clone();
    relabelled.audience = Audience::Public;
    assert_eq!(
        private.check(&relabelled),
        vec![PreviewViolation::AudienceRelabelled {
            recorded_public: false,
            shown_public: true
        }]
    );
    let mut widened = policy;
    widened.audience = private_to(&["alice", "bob", "mallory"]);
    assert_eq!(
        private.check(&widened),
        vec![PreviewViolation::PrincipalsChanged]
    );

    // V02 itself never changes an audience in place.
    let mut table = private.table.clone();
    assert!(table.change_audience(private.id, Audience::Public).is_err());
}

#[test]
fn withdrawn_expired_or_stale_publications_are_refused() {
    let fixture = Fixture::new(Audience::Public);
    let policy = fixture.policy();
    let mut withdrawn = Fixture::new(Audience::Public);
    withdrawn.table.withdraw(withdrawn.id).unwrap();
    assert_eq!(
        withdrawn.check(&withdrawn.policy()),
        vec![PreviewViolation::PublicationNotLive]
    );

    let context = PreviewContext {
        table: &fixture.table,
        generation: GENERATION,
        host: &fixture.host,
        domain: &fixture.domain,
        other_previews: &[],
        now: at_seconds(600),
    };
    assert_eq!(
        check_preview(&policy, &context).unwrap_err().violations,
        vec![PreviewViolation::PublicationNotLive]
    );

    let next = GENERATION.next().unwrap();
    let context = PreviewContext {
        generation: next,
        now: NOW,
        ..context
    };
    assert_eq!(
        check_preview(&policy, &context).unwrap_err().violations,
        vec![PreviewViolation::GenerationStale {
            policy: GENERATION,
            current: next
        }]
    );
}

#[test]
fn a_forged_origin_subject_or_expiry_is_refused() {
    let fixture = Fixture::new(Audience::Public);
    let mut neighbour = table("sbx-2");
    let id = publish(&mut neighbour, "web", Audience::Public);
    let foreign = PreviewSubject::of(neighbour.publication(id).unwrap(), GENERATION);

    let mut policy = fixture.policy();
    policy.origin = derive_preview_origin(&foreign, &fixture.domain);
    assert_eq!(
        fixture.check(&policy),
        vec![PreviewViolation::OriginNotDerived]
    );

    let mut policy = fixture.policy();
    policy.subject.sandbox = foreign.sandbox.clone();
    let violations = fixture.check(&policy);
    assert!(violations.contains(&PreviewViolation::SubjectMismatch));
    assert!(violations.contains(&PreviewViolation::OriginNotDerived));

    let mut policy = fixture.policy();
    policy.expires_at = at_seconds(601);
    assert_eq!(
        fixture.check(&policy),
        vec![PreviewViolation::ExpiryBeyondPublication]
    );
}

#[test]
fn preview_responses_are_charged_to_the_published_service_release_channel() {
    let mut fixture = Fixture::new(Audience::Public);
    let mut policy = fixture.policy();
    assert_eq!(
        policy.release_channel,
        ReleaseChannel::PublishedServiceResponse
    );
    let mut policies = BTreeMap::new();
    policies.insert(
        ReleaseChannel::PublishedServiceResponse,
        ChannelPolicy {
            budget_bytes: 1000,
            trust_class: ReleaseTrustClass::PublishedAudience,
        },
    );
    let mut account = ReleaseAccount::new(
        policies,
        GeneralReleaseBudget::with_limit(1 << 20),
        InFlightAllowance {
            bytes: 0,
            documented_reason: "preview responses are counted exactly".to_owned(),
        },
    )
    .unwrap();
    let service = ServiceIdentity::new("web").unwrap();
    let port = DestinationPort::new(8080).unwrap();
    let session = fixture
        .table
        .admit(&service, port, &InboundCaller::Anonymous, NOW)
        .unwrap();
    fixture
        .table
        .respond(&session, 400, &mut account, NOW)
        .unwrap();
    assert_eq!(
        account.used_bytes(ReleaseChannel::PublishedServiceResponse),
        400
    );
    assert!(fixture
        .table
        .respond(&session, 700, &mut account, NOW)
        .is_err());

    for channel in [
        ReleaseChannel::BrowserPreview,
        ReleaseChannel::UserApprovedTransfer,
    ] {
        policy.release_channel = channel;
        assert_eq!(
            fixture.check(&policy),
            vec![PreviewViolation::ReleaseChannelChanged { found: channel }]
        );
    }
}

#[test]
fn every_violation_is_listed_at_once() {
    let fixture = Fixture::new(Audience::Public);
    let mut policy = fixture.policy();
    policy.host_state.cookies = true;
    policy.forwarding.forward_credentials = true;
    policy.response_headers.clear();
    policy.release_channel = ReleaseChannel::Log;
    let violations = fixture.check(&policy);
    assert!(violations.len() >= 10, "{violations:?}");
    assert!(violations.contains(&PreviewViolation::HostCookies));
    assert!(violations.contains(&PreviewViolation::CredentialForwarding));
    assert!(
        violations.contains(&PreviewViolation::ReleaseChannelChanged {
            found: ReleaseChannel::Log
        })
    );
}

#[test]
fn host_application_origins_are_parsed_strictly() {
    for (text, serialized) in [
        ("tauri://localhost", "tauri://localhost"),
        ("http://tauri.localhost", "http://tauri.localhost"),
        (
            "https://App.Example.com:8443",
            "https://app.example.com:8443",
        ),
    ] {
        assert_eq!(
            HostApplicationOrigin::parse(text).unwrap().serialized(),
            serialized
        );
    }
    assert_eq!(
        HostApplicationOrigin::parse("localhost"),
        Err(OriginError::MissingScheme)
    );
    assert_eq!(
        HostApplicationOrigin::parse("HTTPS://app.example.com"),
        Err(OriginError::InvalidScheme)
    );
    for text in [
        "https://app.example.com/path",
        "https://user@app.example.com",
        "https://app.example.com?q",
        "https://[::1]",
    ] {
        assert_eq!(
            HostApplicationOrigin::parse(text),
            Err(OriginError::NotAnOrigin),
            "{text}"
        );
    }
    assert!(matches!(
        HostApplicationOrigin::parse("https://127.0.0.1"),
        Err(OriginError::InvalidHost(_))
    ));
    assert!(matches!(
        HostApplicationOrigin::parse("https://app.example.com:0"),
        Err(OriginError::InvalidPort(_))
    ));
}

#[test]
fn preview_domains_are_parsed_and_classified() {
    let local = PreviewDomain::new("LocalHost", SuffixListing::NotListed).unwrap();
    assert_eq!(
        local.suffix(),
        &PreviewSuffix::SingleLabel("localhost".to_owned())
    );
    assert!(local.is_public_suffix());
    let unlisted = PreviewDomain::new("previews.example.net", SuffixListing::NotListed).unwrap();
    assert!(!unlisted.is_public_suffix());
    assert!(
        PreviewDomain::new("previews.example.net", SuffixListing::DeclaredPublicSuffix)
            .unwrap()
            .is_public_suffix()
    );
    for bad in ["-bad", "bad-", "123", "", "a_b"] {
        assert_eq!(
            PreviewDomain::new(bad, SuffixListing::NotListed),
            Err(OriginError::InvalidLabel),
            "{bad:?}"
        );
    }
    assert!(matches!(
        PreviewDomain::new("a..b", SuffixListing::NotListed),
        Err(OriginError::InvalidHost(_))
    ));
}

#[test]
fn site_relation_follows_the_stated_rules() {
    let cases: [(&str, &str, &[&str], SiteRelation); 9] = [
        (
            "a.example.com",
            "a.example.com",
            &[],
            SiteRelation::SameHost,
        ),
        (
            "a.example.com",
            "b.example.net",
            &[],
            SiteRelation::CrossSite,
        ),
        (
            "p1.localhost",
            "tauri.localhost",
            &[],
            SiteRelation::CrossSite,
        ),
        ("p1.localhost", "localhost", &[], SiteRelation::CrossSite),
        ("x.github.io", "y.github.io", &[], SiteRelation::CrossSite),
        ("a.b.co.uk", "c.d.co.uk", &[], SiteRelation::CrossSite),
        (
            "a.b.co.uk",
            "c.b.co.uk",
            &[],
            SiteRelation::PossiblySameSite {
                common_suffix: "b.co.uk".to_owned(),
            },
        ),
        (
            "p1.previews.example.net",
            "p2.previews.example.net",
            &[],
            SiteRelation::PossiblySameSite {
                common_suffix: "previews.example.net".to_owned(),
            },
        ),
        (
            "p1.previews.example.net",
            "p2.previews.example.net",
            &["previews.example.net"],
            SiteRelation::CrossSite,
        ),
    ];
    for (a, b, declared, expected) in cases {
        assert_eq!(site_relation(a, b, declared), expected, "{a} {b}");
        assert_eq!(site_relation(b, a, declared), expected, "{b} {a}");
    }
}
