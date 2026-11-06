//! Typed fields that identities are built from (§3.2). Each field validates itself and
//! has one canonical form, so equal inputs always encode to equal parts.

use std::fmt;

use crate::foundation::ids::{
    AuthorizationEpoch, Digest, DigestBuilder, ExecutionCategory, ExecutionId,
};

use super::encoding::{Encode, Encoding, TOKEN_PREFIX_DOMAIN};
use super::error::{IdentityError, PathProblem};

/// Longest accepted [`Label`], in bytes.
pub const MAX_LABEL_BYTES: usize = 256;

/// A short text field of an identity, such as a runner name, a version or a licence
/// (§3.2).
///
/// 1–256 bytes of UTF-8 without control characters or surrounding whitespace, compared
/// byte for byte. A label never makes two identities equal on its own (line 504).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Label(String);

impl Label {
    /// Refuses an empty or over-long label, control characters and surrounding
    /// whitespace.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdentityError::EmptyLabel);
        }
        if value.len() > MAX_LABEL_BYTES {
            return Err(IdentityError::LabelTooLong {
                max_bytes: MAX_LABEL_BYTES,
            });
        }
        if value.chars().any(char::is_control) {
            return Err(IdentityError::LabelControlCharacter);
        }
        if value.trim() != value.as_str() {
            return Err(IdentityError::LabelSurroundingWhitespace);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Label {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Encode for Label {
    fn encode(&self, out: &mut Encoding) {
        out.text(&self.0);
    }
}

/// A component and its exact version, such as a runner, an architecture adapter, a
/// kernel layout or a processed-weight format (§3.2 item 3).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct VersionedName {
    pub name: Label,
    pub version: Label,
}

impl VersionedName {
    /// Both parts are [`Label`]s.
    pub fn new(name: &str, version: &str) -> Result<Self, IdentityError> {
        Ok(Self {
            name: Label::new(name)?,
            version: Label::new(version)?,
        })
    }
}

impl Encode for VersionedName {
    fn encode(&self, out: &mut Encoding) {
        out.item(&self.name).item(&self.version);
    }
}

/// Longest accepted [`RelativePath`], in bytes.
pub const MAX_PATH_BYTES: usize = 1024;

/// A file's path inside a source in its one canonical form: relative, separated by '/',
/// without empty, '.' or '..' segments, backslashes or colons (§3.2 item 1).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelativePath(String);

impl RelativePath {
    /// Refuses any path without one canonical relative form; see [`PathProblem`].
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        let problem = if value.is_empty() {
            Some(PathProblem::Empty)
        } else if value.len() > MAX_PATH_BYTES {
            Some(PathProblem::TooLong)
        } else if value.chars().any(char::is_control) {
            Some(PathProblem::ControlCharacter)
        } else if value.contains('\\') {
            Some(PathProblem::Backslash)
        } else if value.contains(':') {
            Some(PathProblem::Colon)
        } else if value.starts_with('/') {
            Some(PathProblem::Absolute)
        } else if value.split('/').any(str::is_empty) {
            Some(PathProblem::EmptySegment)
        } else if value
            .split('/')
            .any(|segment| segment == "." || segment == "..")
        {
            Some(PathProblem::DotSegment)
        } else {
            None
        };
        match problem {
            Some(problem) => Err(IdentityError::InvalidPath { problem }),
            None => Ok(Self(value)),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Encode for RelativePath {
    fn encode(&self, out: &mut Encoding) {
        out.text(&self.0);
    }
}

/// An immutable revision: a full Git commit hash of 40 (SHA-1) or 64 (SHA-256)
/// hexadecimal digits, kept in lowercase (§3.2 item 1). Branch and tag names can move, so
/// they are refused.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CommitId(String);

impl CommitId {
    /// Refuses anything but 40 or 64 hexadecimal digits; stores them in lowercase.
    pub fn new(value: &str) -> Result<Self, IdentityError> {
        if matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            Ok(Self(value.to_ascii_lowercase()))
        } else {
            Err(IdentityError::NotAnImmutableRevision)
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Encode for CommitId {
    fn encode(&self, out: &mut Encoding) {
        out.text(&self.0);
    }
}

/// An exact element type of weights or KV entries (§3.2 item 2: "exact dtype").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Dtype {
    Float64,
    Float32,
    Float16,
    BFloat16,
    Float8E4M3,
    Float8E5M2,
    Float4E2M1,
    Int8,
    UInt8,
    Int4,
}

impl Dtype {
    pub const ALL: [Self; 10] = [
        Self::Float64,
        Self::Float32,
        Self::Float16,
        Self::BFloat16,
        Self::Float8E4M3,
        Self::Float8E5M2,
        Self::Float4E2M1,
        Self::Int8,
        Self::UInt8,
        Self::Int4,
    ];

    /// Bits per value. Types of 8 bits or fewer count as quantized (§1.3).
    pub const fn bits(self) -> u8 {
        match self {
            Self::Float64 => 64,
            Self::Float32 => 32,
            Self::Float16 | Self::BFloat16 => 16,
            Self::Float8E4M3 | Self::Float8E5M2 | Self::Int8 | Self::UInt8 => 8,
            Self::Float4E2M1 | Self::Int4 => 4,
        }
    }

    /// Whether converting `self` to `wider` keeps every value exactly (§1.3): F16 or BF16
    /// to F32 or F64, and F32 to F64. Types of 8 bits or fewer carry quantization scales
    /// and integers carry quantized codes, so converting from or to them is never exact.
    pub const fn widens_exactly_to(self, wider: Self) -> bool {
        matches!(
            (self, wider),
            (
                Self::Float16 | Self::BFloat16,
                Self::Float32 | Self::Float64
            ) | (Self::Float32, Self::Float64)
        )
    }

    /// The stable tag in the canonical encoding.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Float64 => "f64",
            Self::Float32 => "f32",
            Self::Float16 => "f16",
            Self::BFloat16 => "bf16",
            Self::Float8E4M3 => "f8e4m3",
            Self::Float8E5M2 => "f8e5m2",
            Self::Float4E2M1 => "f4e2m1",
            Self::Int8 => "i8",
            Self::UInt8 => "u8",
            Self::Int4 => "i4",
        }
    }
}

impl Encode for Dtype {
    fn encode(&self, out: &mut Encoding) {
        out.tag(self.tag());
    }
}

/// Exact quantization choices (§3.2 item 2; §3.3 "exact quantization parameters").
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QuantizationScheme {
    method: VersionedName,
    weight_bits: u8,
    group_size: Option<u32>,
    parameters: Digest,
}

impl QuantizationScheme {
    /// `weight_bits` is 1–16 and a group size, when given, is above zero. `parameters` is
    /// the digest of the exact scales, zero points and calibration.
    pub fn new(
        method: VersionedName,
        weight_bits: u8,
        group_size: Option<u32>,
        parameters: Digest,
    ) -> Result<Self, IdentityError> {
        if !(1..=16).contains(&weight_bits) {
            return Err(IdentityError::QuantizationBits { bits: weight_bits });
        }
        if group_size == Some(0) {
            return Err(IdentityError::ZeroGroupSize);
        }
        Ok(Self {
            method,
            weight_bits,
            group_size,
            parameters,
        })
    }

    pub fn method(&self) -> &VersionedName {
        &self.method
    }

    pub fn weight_bits(&self) -> u8 {
        self.weight_bits
    }

    pub fn group_size(&self) -> Option<u32> {
        self.group_size
    }

    pub fn parameters(&self) -> &Digest {
        &self.parameters
    }
}

impl Encode for QuantizationScheme {
    fn encode(&self, out: &mut Encoding) {
        out.item(&self.method)
            .u64(self.weight_bits.into())
            .option(self.group_size.map(u64::from).as_ref())
            .item(&self.parameters);
    }
}

/// Whether values are quantized, and exactly how (§3.2 item 2). Any scheme is an
/// approximation that needs explicit configuration (§1.3; see `FidelityConfiguration`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Quantization {
    None,
    Scheme(QuantizationScheme),
}

impl Encode for Quantization {
    fn encode(&self, out: &mut Encoding) {
        match self {
            Self::None => {
                out.tag("none");
            }
            Self::Scheme(scheme) => {
                out.tag("scheme").item(scheme);
            }
        }
    }
}

/// The authority a placement or session is bound to (S3.1): its parent execution and,
/// where the runtime has one, the VM authorization epoch.
///
/// Inside a VM sandbox the epoch is required. A labelled runtime (VM-D4–VM-D6) binds an
/// epoch when it has one. Raising the epoch changes every identity bound to it, so
/// nothing bound to an older epoch matches again.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AuthorityBinding {
    parent: ExecutionId,
    category: ExecutionCategory,
    epoch: Option<AuthorizationEpoch>,
}

impl AuthorityBinding {
    /// Refuses a VM sandbox binding without its authorization epoch (S3.1).
    pub fn new(
        parent: ExecutionId,
        category: ExecutionCategory,
        epoch: Option<AuthorizationEpoch>,
    ) -> Result<Self, IdentityError> {
        if category.is_vm_sandbox() && epoch.is_none() {
            return Err(IdentityError::MissingAuthorizationEpoch);
        }
        Ok(Self {
            parent,
            category,
            epoch,
        })
    }

    pub fn parent(&self) -> &ExecutionId {
        &self.parent
    }

    pub fn category(&self) -> ExecutionCategory {
        self.category
    }

    pub fn epoch(&self) -> Option<AuthorizationEpoch> {
        self.epoch
    }
}

impl Encode for AuthorityBinding {
    fn encode(&self, out: &mut Encoding) {
        out.item(&self.parent)
            .item(&self.category)
            .option(self.epoch.as_ref());
    }
}

/// The exact token prefix of a session or KV block (§3.2 item 6; FAST-03 "prefix"): a
/// digest of the token IDs in order, and their count.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TokenPrefix {
    digest: Digest,
    token_count: u64,
}

impl TokenPrefix {
    /// Token order carries meaning, so the IDs are hashed in the order given.
    pub fn from_token_ids(token_ids: &[u32]) -> Self {
        let mut bytes = Vec::with_capacity(token_ids.len().saturating_mul(4));
        for token in token_ids {
            bytes.extend_from_slice(&token.to_be_bytes());
        }
        let token_count = u64::try_from(token_ids.len()).unwrap_or(u64::MAX);
        let digest = DigestBuilder::new(TOKEN_PREFIX_DOMAIN)
            .u64(token_count)
            .bytes(&bytes)
            .finish();
        Self {
            digest,
            token_count,
        }
    }

    pub fn digest(&self) -> &Digest {
        &self.digest
    }

    pub fn token_count(&self) -> u64 {
        self.token_count
    }
}

impl Encode for TokenPrefix {
    fn encode(&self, out: &mut Encoding) {
        out.item(&self.digest).u64(self.token_count);
    }
}

/// How token positions are encoded, such as RoPE with its base and scaling (§3.2 item 6;
/// FAST-03 "position").
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PositionalEncoding {
    pub scheme: VersionedName,
    pub parameters: Digest,
}

impl Encode for PositionalEncoding {
    fn encode(&self, out: &mut Encoding) {
        out.item(&self.scheme).item(&self.parameters);
    }
}

/// How KV entries are represented (§3.2 item 6 "KV representation"; FAST-03 "cache
/// representation"): element type, quantization, tokens per block and layout.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KvRepresentation {
    dtype: Dtype,
    quantization: Quantization,
    block_tokens: u32,
    layout: VersionedName,
}

impl KvRepresentation {
    /// Refuses a block of zero tokens.
    pub fn new(
        dtype: Dtype,
        quantization: Quantization,
        block_tokens: u32,
        layout: VersionedName,
    ) -> Result<Self, IdentityError> {
        if block_tokens == 0 {
            return Err(IdentityError::ZeroBlockTokens);
        }
        Ok(Self {
            dtype,
            quantization,
            block_tokens,
            layout,
        })
    }

    pub fn dtype(&self) -> Dtype {
        self.dtype
    }

    pub fn quantization(&self) -> &Quantization {
        &self.quantization
    }

    pub fn block_tokens(&self) -> u32 {
        self.block_tokens
    }

    pub fn layout(&self) -> &VersionedName {
        &self.layout
    }
}

impl Encode for KvRepresentation {
    fn encode(&self, out: &mut Encoding) {
        out.item(&self.dtype)
            .item(&self.quantization)
            .u64(self.block_tokens.into())
            .item(&self.layout);
    }
}
