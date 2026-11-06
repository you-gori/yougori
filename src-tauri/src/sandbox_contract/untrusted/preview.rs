//! Preview origin policy (VM §4.7 line 2038: "serve previews on isolated origins, with no
//! implicit host application session or file access"; line 2034: "never silently relabel
//! public as private"; VM-CP-28 "an HTML preview is served from an isolated origin";
//! VM-P03 and VM-P35).
//!
//! A preview origin is derived from the V02 [`Publication`] and the sandbox boot
//! generation: `https://p<40 hex digits>.<suffix>`, unique per publication and
//! generation. [`PreviewPolicy`] is the record a later preview server must honour: the
//! guest service as the only source, no host application cookies, session or storage,
//! no `file://` or host-path access, credentials stripped from forwarded requests, the
//! response headers it must send, the audience exactly as V02 recorded it, and the
//! release channel its responses are charged to. [`check_preview`] refuses a policy that
//! violates any of these and lists every violation.
//!
//! Same-site is decided without the Public Suffix List, which this layer cannot read:
//! two hosts count as cross-site only when their longest common suffix is empty, a single
//! label (a public suffix under the list's default rule), a suffix in V02's
//! [`SHARED_SUFFIXES`] or the preview suffix the deployment declares listed. Anything
//! else is treated as possibly same-site and refused. The declaration that a
//! multi-label preview suffix is listed is a deployment fact this layer cannot verify.
//!
//! Nothing here serves a preview or sends a header.

use std::collections::BTreeSet;
use std::fmt;

use crate::foundation::ids::{DigestBuilder, ExecutionId, MonotonicTime, SandboxBootGeneration};
use crate::sandbox_contract::destinations::{
    Audience, AuthenticationMode, CanonicalName, DestinationPort, IngressTable, NameError,
    Publication, PublicationId, ReleaseChannel, ServiceIdentity, RESERVED_CREDENTIAL_HEADERS,
    SHARED_SUFFIXES,
};

/// Digest domain of preview origin labels.
pub const PREVIEW_ORIGIN_DOMAIN: &str = "yougori/sandbox/untrusted/preview-origin/v1";

/// CSP sandbox tokens a preview may carry. `allow-same-origin`, every top-navigation
/// token, `allow-popups-to-escape-sandbox`, `allow-downloads` and storage-access tokens
/// are refused, as is any token not listed.
pub const PERMITTED_SANDBOX_TOKENS: [&str; 4] = [
    "allow-scripts",
    "allow-forms",
    "allow-modals",
    "allow-popups",
];

/// Features the Permissions-Policy header must deny (VM-P03: no undeclared clipboard,
/// USB or other host device exposure).
pub const REQUIRED_PERMISSIONS_DENIALS: [&str; 10] = [
    "clipboard-read",
    "clipboard-write",
    "camera",
    "microphone",
    "geolocation",
    "usb",
    "serial",
    "hid",
    "bluetooth",
    "display-capture",
];

const LABEL_HEX_DIGITS: usize = 40;
const CSP: &str = "content-security-policy";
const COOP: &str = "cross-origin-opener-policy";
const CORP: &str = "cross-origin-resource-policy";
const REFERRER: &str = "referrer-policy";
const NOSNIFF: &str = "x-content-type-options";
const PERMISSIONS: &str = "permissions-policy";
const CACHE: &str = "cache-control";

/// Why an origin, host or suffix was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OriginError {
    MissingScheme,
    InvalidScheme,
    /// An origin has no path, query, fragment or user information.
    NotAnOrigin,
    InvalidHost(NameError),
    InvalidPort(NameError),
    InvalidLabel,
}

impl fmt::Display for OriginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingScheme => f.write_str("an origin needs a scheme"),
            Self::InvalidScheme => f.write_str("the scheme is not lowercase letters and digits"),
            Self::NotAnOrigin => {
                f.write_str("an origin has no path, query, fragment or user information")
            }
            Self::InvalidHost(error) => write!(f, "invalid host: {error}"),
            Self::InvalidPort(error) => write!(f, "invalid port: {error}"),
            Self::InvalidLabel => f.write_str("a single-label suffix must be a DNS label"),
        }
    }
}

impl std::error::Error for OriginError {}

/// The origin the host application runs on (§4.7 line 2038: no implicit host application
/// session), such as `tauri://localhost`,
/// `http://tauri.localhost` or `https://app.example.com`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostApplicationOrigin {
    scheme: String,
    host: String,
    port: Option<DestinationPort>,
}

impl HostApplicationOrigin {
    /// Parses `scheme://host[:port]`. The host is `localhost` or a V02 canonical name;
    /// IP literals are refused.
    pub fn parse(text: &str) -> Result<Self, OriginError> {
        let (scheme, rest) = text.split_once("://").ok_or(OriginError::MissingScheme)?;
        if scheme.is_empty()
            || !scheme
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        {
            return Err(OriginError::InvalidScheme);
        }
        if rest.contains(['/', '?', '#', '@', '[', ']']) {
            return Err(OriginError::NotAnOrigin);
        }
        let (host_text, port) = match rest.rsplit_once(':') {
            Some((host, port)) => (
                host,
                Some(DestinationPort::parse(port).map_err(OriginError::InvalidPort)?),
            ),
            None => (rest, None),
        };
        let host = if host_text.eq_ignore_ascii_case("localhost") {
            "localhost".to_owned()
        } else {
            CanonicalName::parse(host_text)
                .map_err(OriginError::InvalidHost)?
                .as_str()
                .to_owned()
        };
        Ok(Self {
            scheme: scheme.to_owned(),
            host,
            port,
        })
    }

    pub fn scheme(&self) -> &str {
        &self.scheme
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    /// The serialized origin, as a CSP source expression names it.
    pub fn serialized(&self) -> String {
        match self.port {
            Some(port) => format!("{}://{}:{}", self.scheme, self.host, port.get()),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }
}

/// The parent domain previews are served under.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviewSuffix {
    /// One DNS label such as `localhost`: a public suffix under the Public Suffix List's
    /// default rule, so each preview below it is its own site.
    SingleLabel(String),
    /// Several labels; each preview below it is its own site only if the suffix is
    /// listed as a public suffix.
    Name(CanonicalName),
}

impl PreviewSuffix {
    pub fn as_str(&self) -> &str {
        match self {
            Self::SingleLabel(label) => label,
            Self::Name(name) => name.as_str(),
        }
    }
}

/// Whether a multi-label preview suffix is listed in the Public Suffix List.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuffixListing {
    /// The deployment declares the suffix listed. This layer cannot verify it.
    DeclaredPublicSuffix,
    NotListed,
}

/// The preview suffix and its listing (§4.7 line 2038 "isolated origins").
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewDomain {
    suffix: PreviewSuffix,
    listing: SuffixListing,
}

impl PreviewDomain {
    pub fn new(suffix: &str, listing: SuffixListing) -> Result<Self, OriginError> {
        let suffix = if suffix.contains('.') {
            PreviewSuffix::Name(CanonicalName::parse(suffix).map_err(OriginError::InvalidHost)?)
        } else {
            let lower = suffix.to_ascii_lowercase();
            if !is_dns_label(&lower) {
                return Err(OriginError::InvalidLabel);
            }
            PreviewSuffix::SingleLabel(lower)
        };
        Ok(Self { suffix, listing })
    }

    pub fn suffix(&self) -> &PreviewSuffix {
        &self.suffix
    }

    pub const fn listing(&self) -> SuffixListing {
        self.listing
    }

    /// Whether each preview below the suffix is its own site.
    pub fn is_public_suffix(&self) -> bool {
        match self.suffix {
            PreviewSuffix::SingleLabel(_) => true,
            PreviewSuffix::Name(_) => self.listing == SuffixListing::DeclaredPublicSuffix,
        }
    }

    fn declared_public(&self) -> Option<&str> {
        self.is_public_suffix().then(|| self.suffix.as_str())
    }
}

fn is_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && !label.bytes().all(|byte| byte.is_ascii_digit())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

/// What a preview origin is derived from: the V02 publication and the sandbox boot
/// generation (§4.7; VM-CP-28).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewSubject {
    pub sandbox: ExecutionId,
    pub generation: SandboxBootGeneration,
    pub publication: PublicationId,
    pub service: ServiceIdentity,
    pub port: DestinationPort,
    pub published_at: MonotonicTime,
}

impl PreviewSubject {
    pub fn of(publication: &Publication, generation: SandboxBootGeneration) -> Self {
        Self {
            sandbox: publication.sandbox.clone(),
            generation,
            publication: publication.id,
            service: publication.service.clone(),
            port: publication.port,
            published_at: publication.published_at,
        }
    }
}

/// An isolated preview origin (VM-CP-28): `https://` and a host one label below the
/// preview suffix.
/// Only [`derive_preview_origin`] makes one.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PreviewOrigin {
    host: String,
}

impl PreviewOrigin {
    pub fn host(&self) -> &str {
        &self.host
    }

    /// The serialized origin.
    pub fn serialized(&self) -> String {
        format!("https://{}", self.host)
    }
}

/// Derives the preview origin of `subject` under `domain`: unique per sandbox, boot
/// generation and publication (§4.7 line 2038; VM-CP-28).
pub fn derive_preview_origin(subject: &PreviewSubject, domain: &PreviewDomain) -> PreviewOrigin {
    let digest = DigestBuilder::new(PREVIEW_ORIGIN_DOMAIN)
        .str(subject.sandbox.as_str())
        .u64(subject.generation.get())
        .u64(subject.publication.get())
        .str(subject.service.as_str())
        .u64(u64::from(subject.port.get()))
        .u64(subject.published_at.as_nanos())
        .str(domain.suffix.as_str())
        .finish();
    let hex = digest.to_hex();
    let label = hex.get(..LABEL_HEX_DIGITS).unwrap_or(&hex);
    PreviewOrigin {
        host: format!("p{label}.{}", domain.suffix.as_str()),
    }
}

/// How two hosts relate as sites, decided without the Public Suffix List (§4.7 line 2038
/// "isolated origins").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SiteRelation {
    SameHost,
    CrossSite,
    /// They share a suffix that is not known to be public, so they may be one site.
    PossiblySameSite {
        common_suffix: String,
    },
}

/// Relates hosts `a` and `b`. Their longest common label suffix must be empty, one label,
/// in V02's [`SHARED_SUFFIXES`] or in `declared_public` for them to be cross-site; ports
/// and schemes are ignored, which can only make the answer stricter.
pub fn site_relation(a: &str, b: &str, declared_public: &[&str]) -> SiteRelation {
    let a = a.to_ascii_lowercase();
    let b = b.to_ascii_lowercase();
    if a == b {
        return SiteRelation::SameHost;
    }
    let mut common: Vec<&str> = a
        .rsplit('.')
        .zip(b.rsplit('.'))
        .take_while(|(left, right)| left == right)
        .map(|(label, _)| label)
        .collect();
    if common.len() <= 1 {
        return SiteRelation::CrossSite;
    }
    common.reverse();
    let common_suffix = common.join(".");
    if SHARED_SUFFIXES.contains(&common_suffix.as_str())
        || declared_public.contains(&common_suffix.as_str())
    {
        SiteRelation::CrossSite
    } else {
        SiteRelation::PossiblySameSite { common_suffix }
    }
}

/// What a preview serves (§4.7 line 2038 "no implicit ... file access").
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviewSource {
    /// The published guest service; the only accepted source.
    GuestService,
    /// A host path; always refused.
    HostPath { path: String },
    /// A `file://` URL; always refused.
    FileUrl { url: String },
}

/// Host application state a preview could reach. Every field must be false (§4.7 "no
/// implicit host application session").
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HostStateAccess {
    pub cookies: bool,
    pub session: bool,
    pub storage: bool,
}

/// File access a preview could have. Both must be absent (§4.7 "no implicit ... file
/// access"; VM-P03).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FileAccess {
    pub file_urls: bool,
    pub host_paths: Vec<String>,
}

/// How the preview server forwards requests to the guest service (VM-P35: previews
/// cannot inherit host application credentials).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestForwarding {
    /// Must be false: the caller's credentials and the preview's own authentication are
    /// never passed to the guest.
    pub forward_credentials: bool,
    /// Lower-case request headers removed before forwarding; must include V02's
    /// [`RESERVED_CREDENTIAL_HEADERS`].
    pub stripped_request_headers: BTreeSet<String>,
}

/// Who may frame a preview (the CSP `frame-ancestors` of VM-CP-28's isolated origin).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameAncestors {
    /// Nobody (`frame-ancestors 'none'`).
    None,
    /// Only the host application origin, for a UI that embeds the preview.
    HostApplication,
}

/// One response header a later preview server must send, replacing any guest copy
/// (VM-CP-28; VM-P03; VM-P35).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderLine {
    pub name: String,
    pub value: String,
}

impl HeaderLine {
    fn new(name: &str, value: impl Into<String>) -> Self {
        Self {
            name: name.to_owned(),
            value: value.into(),
        }
    }
}

/// The preview policy record (§4.7; VM-CP-28; VM-P03; VM-P33; VM-P35). Fields are public
/// so a later server can read them and a changed copy can be checked; [`check_preview`]
/// is the gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewPolicy {
    pub subject: PreviewSubject,
    pub origin: PreviewOrigin,
    pub source: PreviewSource,
    /// Exactly V02's audience; never relabelled.
    pub audience: Audience,
    pub authentication: AuthenticationMode,
    pub expires_at: MonotonicTime,
    pub host_state: HostStateAccess,
    pub file_access: FileAccess,
    pub forwarding: RequestForwarding,
    pub response_headers: Vec<HeaderLine>,
    /// Where response bytes are charged: V02 charges a publication's responses to
    /// [`ReleaseChannel::PublishedServiceResponse`] (§4.7 line 2032; VM-P33).
    pub release_channel: ReleaseChannel,
}

impl PreviewPolicy {
    /// The strict record for `publication` in boot `generation`.
    pub fn for_publication(
        publication: &Publication,
        generation: SandboxBootGeneration,
        domain: &PreviewDomain,
        host: &HostApplicationOrigin,
        framing: FrameAncestors,
    ) -> Self {
        let subject = PreviewSubject::of(publication, generation);
        let origin = derive_preview_origin(&subject, domain);
        let frame_ancestors = match framing {
            FrameAncestors::None => "'none'".to_owned(),
            FrameAncestors::HostApplication => host.serialized(),
        };
        let permissions = REQUIRED_PERMISSIONS_DENIALS
            .iter()
            .map(|feature| format!("{feature}=()"))
            .collect::<Vec<_>>()
            .join(", ");
        Self {
            subject,
            origin,
            source: PreviewSource::GuestService,
            audience: publication.audience.clone(),
            authentication: publication.authentication,
            expires_at: publication.expires_at,
            host_state: HostStateAccess::default(),
            file_access: FileAccess::default(),
            forwarding: RequestForwarding {
                forward_credentials: false,
                stripped_request_headers: RESERVED_CREDENTIAL_HEADERS
                    .iter()
                    .map(|name| (*name).to_owned())
                    .collect(),
            },
            response_headers: vec![
                HeaderLine::new(
                    "Content-Security-Policy",
                    format!("sandbox allow-scripts allow-forms; frame-ancestors {frame_ancestors}"),
                ),
                HeaderLine::new("Cross-Origin-Opener-Policy", "same-origin"),
                HeaderLine::new("Cross-Origin-Resource-Policy", "same-origin"),
                HeaderLine::new("Referrer-Policy", "no-referrer"),
                HeaderLine::new("X-Content-Type-Options", "nosniff"),
                HeaderLine::new("Permissions-Policy", permissions),
                HeaderLine::new("Cache-Control", "no-store"),
            ],
            release_channel: ReleaseChannel::PublishedServiceResponse,
        }
    }

    /// The audience as the UI must show it, worded from V02's record (line 2034).
    pub fn audience_label(&self) -> String {
        match &self.audience {
            Audience::Public => "public: anyone who has the address".to_owned(),
            Audience::Private { principals } => format!(
                "private: {} named principal(s), {:?} authentication required",
                principals.len(),
                self.authentication
            ),
        }
    }
}

/// What a policy is checked against by [`check_preview`] (§4.7).
#[derive(Clone, Copy, Debug)]
pub struct PreviewContext<'a> {
    /// The sandbox's V02 ingress table, the record of its publications.
    pub table: &'a IngressTable,
    /// The sandbox's current boot generation.
    pub generation: SandboxBootGeneration,
    pub host: &'a HostApplicationOrigin,
    pub domain: &'a PreviewDomain,
    /// Origins of every other live preview, of this sandbox or another.
    pub other_previews: &'a [PreviewOrigin],
    pub now: MonotonicTime,
}

/// One way a preview policy breaks §4.7, VM-CP-28, VM-P03, VM-P33 or VM-P35.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreviewViolation {
    /// The publication is withdrawn, expired or not in this sandbox's table.
    PublicationNotLive,
    /// The subject does not match the live publication.
    SubjectMismatch,
    /// The policy was made for another boot generation.
    GenerationStale {
        policy: SandboxBootGeneration,
        current: SandboxBootGeneration,
    },
    /// The origin is not the one derived from the subject.
    OriginNotDerived,
    /// Previews below a suffix not known to be public would share one site.
    SuffixNotPublic,
    /// The host application lives at or below a multi-label preview suffix. Refused
    /// whatever the declared listing, so a wrong declaration cannot make them one site.
    HostApplicationUnderPreviewSuffix,
    /// The preview may be same-site with the host application; `None` for the same host.
    SameSiteAsHostApplication {
        common_suffix: Option<String>,
    },
    /// Another preview has this origin.
    OriginCollision,
    SameSiteAsOtherPreview {
        other: String,
        common_suffix: String,
    },
    SourceNotGuestService,
    FileUrlAccess,
    HostPathAccess {
        paths: usize,
    },
    HostCookies,
    HostSession,
    HostStorage,
    CredentialForwarding,
    CredentialHeaderNotStripped {
        header: &'static str,
    },
    HeaderMissing {
        name: &'static str,
    },
    HeaderDuplicated {
        name: String,
    },
    HeaderValueWrong {
        name: &'static str,
        required: &'static str,
    },
    SandboxDirectiveMissing,
    SandboxTokenRefused {
        token: String,
    },
    CspDirectiveDuplicated {
        directive: String,
    },
    FrameAncestorsMissing,
    /// `frame-ancestors` names something other than `'none'` or the host application.
    FrameAncestorsTooBroad {
        value: String,
    },
    PermissionNotDenied {
        feature: &'static str,
    },
    /// A public publication shown as private, or the reverse (line 2034).
    AudienceRelabelled {
        recorded_public: bool,
        shown_public: bool,
    },
    PrincipalsChanged,
    AuthenticationChanged {
        recorded: AuthenticationMode,
        shown: AuthenticationMode,
    },
    ExpiryBeyondPublication,
    ReleaseChannelChanged {
        found: ReleaseChannel,
    },
}

/// Every violation found in a preview policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreviewRefusal {
    pub violations: Vec<PreviewViolation>,
}

impl fmt::Display for PreviewRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the preview policy has {} violation(s): {:?}",
            self.violations.len(),
            self.violations
        )
    }
}

impl std::error::Error for PreviewRefusal {}

/// Refuses a preview policy that breaks any rule of §4.7 line 2038, line 2034, VM-CP-28,
/// VM-P03 or VM-P33, listing every violation. Passing is a statement about the record
/// only; it does not show that any server enforces it.
pub fn check_preview(
    policy: &PreviewPolicy,
    context: &PreviewContext<'_>,
) -> Result<(), PreviewRefusal> {
    let mut violations = Vec::new();
    check_subject(policy, context, &mut violations);
    check_sites(policy, context, &mut violations);
    check_access(policy, &mut violations);
    check_headers(policy, context.host, &mut violations);
    if policy.release_channel != ReleaseChannel::PublishedServiceResponse {
        violations.push(PreviewViolation::ReleaseChannelChanged {
            found: policy.release_channel,
        });
    }
    if violations.is_empty() {
        Ok(())
    } else {
        Err(PreviewRefusal { violations })
    }
}

fn check_subject(
    policy: &PreviewPolicy,
    context: &PreviewContext<'_>,
    out: &mut Vec<PreviewViolation>,
) {
    if policy.subject.generation != context.generation {
        out.push(PreviewViolation::GenerationStale {
            policy: policy.subject.generation,
            current: context.generation,
        });
    }
    let live = context
        .table
        .active(context.now)
        .into_iter()
        .find(|publication| publication.id == policy.subject.publication);
    match live {
        None => out.push(PreviewViolation::PublicationNotLive),
        Some(publication) => {
            if PreviewSubject::of(publication, policy.subject.generation) != policy.subject {
                out.push(PreviewViolation::SubjectMismatch);
            }
            check_audience(policy, publication, out);
            if policy.expires_at > publication.expires_at {
                out.push(PreviewViolation::ExpiryBeyondPublication);
            }
        }
    }
    if derive_preview_origin(&policy.subject, context.domain) != policy.origin {
        out.push(PreviewViolation::OriginNotDerived);
    }
}

fn check_audience(
    policy: &PreviewPolicy,
    publication: &Publication,
    out: &mut Vec<PreviewViolation>,
) {
    let recorded_public = publication.audience == Audience::Public;
    let shown_public = policy.audience == Audience::Public;
    if recorded_public != shown_public {
        out.push(PreviewViolation::AudienceRelabelled {
            recorded_public,
            shown_public,
        });
    } else if policy.audience != publication.audience {
        out.push(PreviewViolation::PrincipalsChanged);
    }
    if policy.authentication != publication.authentication {
        out.push(PreviewViolation::AuthenticationChanged {
            recorded: publication.authentication,
            shown: policy.authentication,
        });
    }
}

fn check_sites(
    policy: &PreviewPolicy,
    context: &PreviewContext<'_>,
    out: &mut Vec<PreviewViolation>,
) {
    if !context.domain.is_public_suffix() {
        out.push(PreviewViolation::SuffixNotPublic);
    }
    // A single-label suffix is public by the list's default rule; a multi-label one
    // rests on the deployment's declaration, so the host application may not sit under it.
    if let PreviewSuffix::Name(suffix) = &context.domain.suffix {
        let host = context.host.host();
        if host == suffix.as_str()
            || host
                .strip_suffix(suffix.as_str())
                .is_some_and(|rest| rest.ends_with('.'))
        {
            out.push(PreviewViolation::HostApplicationUnderPreviewSuffix);
        }
    }
    let declared: Vec<&str> = context.domain.declared_public().into_iter().collect();
    match site_relation(policy.origin.host(), context.host.host(), &declared) {
        SiteRelation::CrossSite => {}
        SiteRelation::SameHost => out.push(PreviewViolation::SameSiteAsHostApplication {
            common_suffix: None,
        }),
        SiteRelation::PossiblySameSite { common_suffix } => {
            out.push(PreviewViolation::SameSiteAsHostApplication {
                common_suffix: Some(common_suffix),
            })
        }
    }
    for other in context.other_previews {
        match site_relation(policy.origin.host(), other.host(), &declared) {
            SiteRelation::CrossSite => {}
            SiteRelation::SameHost => out.push(PreviewViolation::OriginCollision),
            SiteRelation::PossiblySameSite { common_suffix } => {
                out.push(PreviewViolation::SameSiteAsOtherPreview {
                    other: other.serialized(),
                    common_suffix,
                })
            }
        }
    }
}

fn check_access(policy: &PreviewPolicy, out: &mut Vec<PreviewViolation>) {
    if policy.source != PreviewSource::GuestService {
        out.push(PreviewViolation::SourceNotGuestService);
    }
    if policy.file_access.file_urls {
        out.push(PreviewViolation::FileUrlAccess);
    }
    if !policy.file_access.host_paths.is_empty() {
        out.push(PreviewViolation::HostPathAccess {
            paths: policy.file_access.host_paths.len(),
        });
    }
    if policy.host_state.cookies {
        out.push(PreviewViolation::HostCookies);
    }
    if policy.host_state.session {
        out.push(PreviewViolation::HostSession);
    }
    if policy.host_state.storage {
        out.push(PreviewViolation::HostStorage);
    }
    if policy.forwarding.forward_credentials {
        out.push(PreviewViolation::CredentialForwarding);
    }
    for header in RESERVED_CREDENTIAL_HEADERS {
        if !policy.forwarding.stripped_request_headers.contains(header) {
            out.push(PreviewViolation::CredentialHeaderNotStripped { header });
        }
    }
}

fn check_headers(
    policy: &PreviewPolicy,
    host: &HostApplicationOrigin,
    out: &mut Vec<PreviewViolation>,
) {
    let mut seen = BTreeSet::new();
    for line in &policy.response_headers {
        let name = line.name.to_ascii_lowercase();
        if !seen.insert(name.clone()) {
            out.push(PreviewViolation::HeaderDuplicated { name });
        }
    }
    let value = |name: &str| {
        policy
            .response_headers
            .iter()
            .find(|line| line.name.eq_ignore_ascii_case(name))
            .map(|line| line.value.trim().to_owned())
    };
    match value(CSP) {
        None => out.push(PreviewViolation::HeaderMissing { name: CSP }),
        Some(csp) => check_csp(&csp, host, out),
    }
    for (name, required) in [
        (COOP, "same-origin"),
        (CORP, "same-origin"),
        (REFERRER, "no-referrer"),
        (NOSNIFF, "nosniff"),
        (CACHE, "no-store"),
    ] {
        match value(name) {
            None => out.push(PreviewViolation::HeaderMissing { name }),
            Some(found) if !found.eq_ignore_ascii_case(required) => {
                out.push(PreviewViolation::HeaderValueWrong { name, required })
            }
            Some(_) => {}
        }
    }
    match value(PERMISSIONS) {
        None => out.push(PreviewViolation::HeaderMissing { name: PERMISSIONS }),
        Some(permissions) => {
            let denied: BTreeSet<String> = permissions
                .split(',')
                .map(|item| {
                    item.split_whitespace()
                        .collect::<String>()
                        .to_ascii_lowercase()
                })
                .collect();
            for feature in REQUIRED_PERMISSIONS_DENIALS {
                if !denied.contains(&format!("{feature}=()")) {
                    out.push(PreviewViolation::PermissionNotDenied { feature });
                }
            }
        }
    }
}

fn check_csp(csp: &str, host: &HostApplicationOrigin, out: &mut Vec<PreviewViolation>) {
    let mut directives = BTreeSet::new();
    let mut sandbox = None;
    let mut frame_ancestors = None;
    for directive in csp.split(';') {
        let mut tokens = directive.split_whitespace();
        let Some(name) = tokens.next().map(str::to_ascii_lowercase) else {
            continue;
        };
        if !directives.insert(name.clone()) {
            out.push(PreviewViolation::CspDirectiveDuplicated { directive: name });
            continue;
        }
        let values: Vec<String> = tokens.map(str::to_owned).collect();
        match name.as_str() {
            "sandbox" => sandbox = Some(values),
            "frame-ancestors" => frame_ancestors = Some(values),
            _ => {}
        }
    }
    match sandbox {
        None => out.push(PreviewViolation::SandboxDirectiveMissing),
        Some(tokens) => {
            for token in tokens {
                if !PERMITTED_SANDBOX_TOKENS.contains(&token.to_ascii_lowercase().as_str()) {
                    out.push(PreviewViolation::SandboxTokenRefused { token });
                }
            }
        }
    }
    match frame_ancestors {
        None => out.push(PreviewViolation::FrameAncestorsMissing),
        Some(values) => {
            let accepted = match values.as_slice() {
                [only] => only == "'none'" || *only == host.serialized(),
                _ => false,
            };
            if !accepted {
                out.push(PreviewViolation::FrameAncestorsTooBroad {
                    value: values.join(" "),
                });
            }
        }
    }
}
