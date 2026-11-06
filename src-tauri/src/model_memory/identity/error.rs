//! Why identity inputs were refused.

use std::fmt;

/// Why a path is not a canonical relative path (§3.2 item 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathProblem {
    Empty,
    TooLong,
    ControlCharacter,
    Backslash,
    Colon,
    Absolute,
    EmptySegment,
    DotSegment,
}

impl fmt::Display for PathProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Empty => "the path is empty",
            Self::TooLong => "the path is too long",
            Self::ControlCharacter => "the path contains a control character",
            Self::Backslash => "the path uses '\\'; separate segments with '/'",
            Self::Colon => "the path contains ':', which names a drive or stream on Windows",
            Self::Absolute => "the path starts with '/'; it must be relative to the source",
            Self::EmptySegment => "the path has an empty segment",
            Self::DotSegment => "the path has a '.' or '..' segment",
        })
    }
}

/// Why typed identity inputs were refused (§3.2). Nothing is clamped, repaired or
/// guessed: an identity exists only for valid inputs in their canonical form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    EmptyLabel,
    LabelTooLong {
        max_bytes: usize,
    },
    LabelControlCharacter,
    /// Leading or trailing whitespace would give one label two forms.
    LabelSurroundingWhitespace,
    InvalidPath {
        problem: PathProblem,
    },
    /// Not a full commit hash. Branch and tag names can move, so they are refused.
    NotAnImmutableRevision,
    /// A repository source must name a commit (§3.2 item 1).
    RepositoryNeedsCommit,
    NoSourceFiles,
    DuplicateSourceFile {
        path: String,
    },
    NoGpuArchitecture,
    ZeroParallelism {
        dimension: &'static str,
    },
    /// Bits per weight outside 1–16.
    QuantizationBits {
        bits: u8,
    },
    ZeroGroupSize,
    ZeroBlockTokens,
    /// A merge scale that is zero, NaN or infinite.
    InvalidMergeScale,
    NoMergedAdapters,
    /// A binding inside a VM sandbox without its authorization epoch (S3.1).
    MissingAuthorizationEpoch,
    /// A generation that would not move forward (S3.1).
    GenerationNotAfter {
        field: &'static str,
        current: u64,
        proposed: u64,
    },
    /// A CUDA graph that declares no resources cannot be validated (§1.1, line 305).
    NoGraphResources,
    DuplicateGraphResource {
        role: String,
    },
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLabel => f.write_str("a label is empty"),
            Self::LabelTooLong { max_bytes } => {
                write!(f, "a label is longer than {max_bytes} bytes")
            }
            Self::LabelControlCharacter => f.write_str("a label contains a control character"),
            Self::LabelSurroundingWhitespace => {
                f.write_str("a label starts or ends with whitespace")
            }
            Self::InvalidPath { problem } => write!(f, "invalid source path: {problem}"),
            Self::NotAnImmutableRevision => f.write_str(
                "a revision must be a full 40- or 64-digit commit hash; branch and tag names move",
            ),
            Self::RepositoryNeedsCommit => f.write_str("a repository source must name a commit"),
            Self::NoSourceFiles => f.write_str("a source lists no files"),
            Self::DuplicateSourceFile { path } => write!(f, "the source lists {path:?} twice"),
            Self::NoGpuArchitecture => f.write_str("an execution names no GPU architecture"),
            Self::ZeroParallelism { dimension } => write!(f, "{dimension} is zero"),
            Self::QuantizationBits { bits } => {
                write!(f, "{bits} bits per weight is outside 1-16")
            }
            Self::ZeroGroupSize => f.write_str("a quantization group size is zero"),
            Self::ZeroBlockTokens => f.write_str("a KV block holds zero tokens"),
            Self::InvalidMergeScale => f.write_str("a merge scale must be finite and not zero"),
            Self::NoMergedAdapters => f.write_str("a merged-adapter recipe lists no adapters"),
            Self::MissingAuthorizationEpoch => {
                f.write_str("a binding inside a VM sandbox needs its authorization epoch")
            }
            Self::GenerationNotAfter {
                field,
                current,
                proposed,
            } => write!(
                f,
                "{field} generation {proposed} does not follow {current}; generations only move forward"
            ),
            Self::NoGraphResources => f.write_str("a CUDA graph declares no resources"),
            Self::DuplicateGraphResource { role } => {
                write!(f, "the CUDA graph declares resource {role:?} twice")
            }
        }
    }
}

impl std::error::Error for IdentityError {}
