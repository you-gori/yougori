//! Names, paths, revisions and tensor element types of the sidecar manifest (GPU part
//! §3.3: provenance and tensor index).

use std::fmt;

/// Why a name, path, token or revision was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NameError {
    Empty,
    TooLong {
        max_bytes: usize,
    },
    InvalidCharacter {
        character: char,
    },
    /// A path component that is empty, `.` or `..`, ends in a dot or a space, or names a
    /// Windows device such as `CON`.
    InvalidComponent,
    /// Not 40 hexadecimal characters: a branch or tag name is not an immutable revision.
    NotACommit,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the name is empty"),
            Self::TooLong { max_bytes } => write!(f, "the name is longer than {max_bytes} bytes"),
            Self::InvalidCharacter { character } => {
                write!(f, "the name contains {character:?}")
            }
            Self::InvalidComponent => f.write_str(
                "a path component is empty, '.' or '..', ends in a dot or a space, or names a \
                 device",
            ),
            Self::NotACommit => f.write_str(
                "a revision is a 40-character hexadecimal commit, not a branch or tag name",
            ),
        }
    }
}

impl std::error::Error for NameError {}

/// Longest accepted [`RelativePath`], in bytes.
pub const MAX_PATH_BYTES: usize = 1_024;
/// Longest accepted path component, in bytes.
pub const MAX_PATH_COMPONENT_BYTES: usize = 255;

/// A file inside a model source or the catalog: relative, '/'-separated and normalised.
///
/// Absolute paths, `.` and `..`, empty components, backslashes, drive and stream
/// separators, control characters and Windows device names are unrepresentable, so a
/// listed file never names anything outside the root the caller passes in.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelativePath(String);

impl RelativePath {
    pub fn new(path: impl Into<String>) -> Result<Self, NameError> {
        let path = path.into();
        if path.is_empty() {
            return Err(NameError::Empty);
        }
        if path.len() > MAX_PATH_BYTES {
            return Err(NameError::TooLong {
                max_bytes: MAX_PATH_BYTES,
            });
        }
        if let Some(character) = path.chars().find(|character| {
            character.is_control()
                || matches!(character, '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
        }) {
            return Err(NameError::InvalidCharacter { character });
        }
        if !path.split('/').all(valid_component) {
            return Err(NameError::InvalidComponent);
        }
        Ok(Self(path))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The path's components, outermost first.
    pub fn components(&self) -> std::str::Split<'_, char> {
        self.0.split('/')
    }

    /// The ASCII case-folded form. Two paths with the same folded form name one file on a
    /// case-insensitive filesystem, so a listing may not hold both.
    pub fn folded(&self) -> String {
        self.0.to_ascii_lowercase()
    }
}

fn valid_component(component: &str) -> bool {
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.len() > MAX_PATH_COMPONENT_BYTES
        || component.ends_with('.')
        || component.ends_with(' ')
    {
        return false;
    }
    let stem = component
        .split('.')
        .next()
        .unwrap_or(component)
        .to_ascii_uppercase();
    !is_windows_device(&stem)
}

fn is_windows_device(stem: &str) -> bool {
    if matches!(stem, "CON" | "PRN" | "AUX" | "NUL") {
        return true;
    }
    let numbered = stem.starts_with("COM") || stem.starts_with("LPT");
    numbered
        && stem.len() == 4
        && stem
            .as_bytes()
            .get(3)
            .is_some_and(|digit| (b'1'..=b'9').contains(digit))
}

impl fmt::Debug for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RelativePath({:?})", self.0)
    }
}

impl fmt::Display for RelativePath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Longest accepted [`Token`], in bytes.
pub const MAX_TOKEN_BYTES: usize = 256;

/// A short identifier of printable ASCII without spaces: versions, runner, adapter,
/// layout and kernel identifiers, origins and quantization parameters (§3.3 semantics and
/// execution ABI). Values are compared exactly; no normalisation is applied.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Token(String);

impl Token {
    pub fn new(text: impl Into<String>) -> Result<Self, NameError> {
        let text = text.into();
        if text.is_empty() {
            return Err(NameError::Empty);
        }
        if text.len() > MAX_TOKEN_BYTES {
            return Err(NameError::TooLong {
                max_bytes: MAX_TOKEN_BYTES,
            });
        }
        if let Some(character) = text.chars().find(|character| !character.is_ascii_graphic()) {
            return Err(NameError::InvalidCharacter { character });
        }
        Ok(Self(text))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Token({:?})", self.0)
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Longest [`TensorName`] any manifest may declare; its own bound may be lower.
pub const MAX_TENSOR_NAME_BYTES: usize = 1_024;

/// A tensor or buffer name: UTF-8 without control characters (§3.3 tensor index).
/// Names are compared byte for byte.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TensorName(String);

impl TensorName {
    pub fn new(name: impl Into<String>) -> Result<Self, NameError> {
        let name = name.into();
        if name.is_empty() {
            return Err(NameError::Empty);
        }
        if name.len() > MAX_TENSOR_NAME_BYTES {
            return Err(NameError::TooLong {
                max_bytes: MAX_TENSOR_NAME_BYTES,
            });
        }
        if let Some(character) = name.chars().find(|character| character.is_control()) {
            return Err(NameError::InvalidCharacter { character });
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for TensorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "TensorName({:?})", self.0)
    }
}

impl fmt::Display for TensorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An immutable Git commit (§3.3 provenance: immutable source revision). Branch and tag
/// names are unrepresentable: they can move.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GitCommit([u8; 20]);

impl GitCommit {
    /// Accepts exactly 40 hexadecimal characters.
    pub fn from_hex(text: &str) -> Result<Self, NameError> {
        let mut bytes = [0u8; 20];
        hex::decode_to_slice(text, &mut bytes).map_err(|_| NameError::NotACommit)?;
        Ok(Self(bytes))
    }

    pub const fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 20] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for GitCommit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GitCommit({})", self.to_hex())
    }
}

/// Element type of a tensor whose elements are stored one after another: the safetensors
/// dtypes, which include the plain GGML types (§3.3 tensor index: dtype).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ElementType {
    Bool,
    U8,
    I8,
    F8E5m2,
    F8E4m3,
    F8E8m0,
    I16,
    U16,
    F16,
    Bf16,
    I32,
    U32,
    F32,
    F64,
    I64,
    U64,
    F4,
    F6E2m3,
    F6E3m2,
}

impl ElementType {
    pub const ALL: [Self; 19] = [
        Self::Bool,
        Self::U8,
        Self::I8,
        Self::F8E5m2,
        Self::F8E4m3,
        Self::F8E8m0,
        Self::I16,
        Self::U16,
        Self::F16,
        Self::Bf16,
        Self::I32,
        Self::U32,
        Self::F32,
        Self::F64,
        Self::I64,
        Self::U64,
        Self::F4,
        Self::F6E2m3,
        Self::F6E3m2,
    ];

    /// Bits per element.
    pub const fn bits(self) -> u64 {
        match self {
            Self::F4 => 4,
            Self::F6E2m3 | Self::F6E3m2 => 6,
            Self::Bool | Self::U8 | Self::I8 | Self::F8E5m2 | Self::F8E4m3 | Self::F8E8m0 => 8,
            Self::I16 | Self::U16 | Self::F16 | Self::Bf16 => 16,
            Self::I32 | Self::U32 | Self::F32 => 32,
            Self::F64 | Self::I64 | Self::U64 => 64,
        }
    }

    /// The dtype string of a safetensors header.
    pub const fn safetensors_name(self) -> &'static str {
        match self {
            Self::Bool => "BOOL",
            Self::U8 => "U8",
            Self::I8 => "I8",
            Self::F8E5m2 => "F8_E5M2",
            Self::F8E4m3 => "F8_E4M3",
            Self::F8E8m0 => "F8_E8M0",
            Self::I16 => "I16",
            Self::U16 => "U16",
            Self::F16 => "F16",
            Self::Bf16 => "BF16",
            Self::I32 => "I32",
            Self::U32 => "U32",
            Self::F32 => "F32",
            Self::F64 => "F64",
            Self::I64 => "I64",
            Self::U64 => "U64",
            Self::F4 => "F4",
            Self::F6E2m3 => "F6_E2M3",
            Self::F6E3m2 => "F6_E3M2",
        }
    }

    pub fn from_safetensors_name(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|element| element.safetensors_name() == name)
    }

    /// Stable code in the canonical encoding.
    pub(super) const fn code(self) -> u8 {
        match self {
            Self::Bool => 1,
            Self::U8 => 2,
            Self::I8 => 3,
            Self::F8E5m2 => 4,
            Self::F8E4m3 => 5,
            Self::F8E8m0 => 6,
            Self::I16 => 7,
            Self::U16 => 8,
            Self::F16 => 9,
            Self::Bf16 => 10,
            Self::I32 => 11,
            Self::U32 => 12,
            Self::F32 => 13,
            Self::F64 => 14,
            Self::I64 => 15,
            Self::U64 => 16,
            Self::F4 => 17,
            Self::F6E2m3 => 18,
            Self::F6E3m2 => 19,
        }
    }

    pub(super) fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|element| element.code() == code)
    }
}

/// A GGML block-quantized type: elements are stored in fixed-size blocks along the
/// innermost dimension. Names follow ggml; sizes are ggml-common.h's block structs.
#[allow(non_camel_case_types)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GgmlType {
    Q4_0,
    Q4_1,
    Q5_0,
    Q5_1,
    Q8_0,
    Q8_1,
    Q2_K,
    Q3_K,
    Q4_K,
    Q5_K,
    Q6_K,
    Q8_K,
    IQ2_XXS,
    IQ2_XS,
    IQ3_XXS,
    IQ1_S,
    IQ4_NL,
    IQ3_S,
    IQ2_S,
    IQ4_XS,
    IQ1_M,
    TQ1_0,
    TQ2_0,
    MXFP4,
}

impl GgmlType {
    pub const ALL: [Self; 24] = [
        Self::Q4_0,
        Self::Q4_1,
        Self::Q5_0,
        Self::Q5_1,
        Self::Q8_0,
        Self::Q8_1,
        Self::Q2_K,
        Self::Q3_K,
        Self::Q4_K,
        Self::Q5_K,
        Self::Q6_K,
        Self::Q8_K,
        Self::IQ2_XXS,
        Self::IQ2_XS,
        Self::IQ3_XXS,
        Self::IQ1_S,
        Self::IQ4_NL,
        Self::IQ3_S,
        Self::IQ2_S,
        Self::IQ4_XS,
        Self::IQ1_M,
        Self::TQ1_0,
        Self::TQ2_0,
        Self::MXFP4,
    ];

    /// The ggml type id, elements per block and bytes per block.
    const fn block_layout(self) -> (u32, u64, u64) {
        match self {
            Self::Q4_0 => (2, 32, 18),
            Self::Q4_1 => (3, 32, 20),
            Self::Q5_0 => (6, 32, 22),
            Self::Q5_1 => (7, 32, 24),
            Self::Q8_0 => (8, 32, 34),
            Self::Q8_1 => (9, 32, 36),
            Self::Q2_K => (10, 256, 84),
            Self::Q3_K => (11, 256, 110),
            Self::Q4_K => (12, 256, 144),
            Self::Q5_K => (13, 256, 176),
            Self::Q6_K => (14, 256, 210),
            Self::Q8_K => (15, 256, 292),
            Self::IQ2_XXS => (16, 256, 66),
            Self::IQ2_XS => (17, 256, 74),
            Self::IQ3_XXS => (18, 256, 98),
            Self::IQ1_S => (19, 256, 50),
            Self::IQ4_NL => (20, 32, 18),
            Self::IQ3_S => (21, 256, 110),
            Self::IQ2_S => (22, 256, 82),
            Self::IQ4_XS => (23, 256, 136),
            Self::IQ1_M => (29, 256, 56),
            Self::TQ1_0 => (34, 256, 54),
            Self::TQ2_0 => (35, 256, 66),
            Self::MXFP4 => (39, 32, 17),
        }
    }

    /// The ggml type id stored in GGUF tensor infos.
    pub const fn id(self) -> u32 {
        self.block_layout().0
    }

    pub const fn block_elements(self) -> u64 {
        self.block_layout().1
    }

    pub const fn block_bytes(self) -> u64 {
        self.block_layout().2
    }

    pub fn from_id(id: u32) -> Option<Self> {
        Self::ALL.into_iter().find(|ggml| ggml.id() == id)
    }
}

/// The interpretation of a tensor's element bytes (§3.3 tensor index: dtype).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TensorDtype {
    Element(ElementType),
    Ggml(GgmlType),
}

impl TensorDtype {
    /// The dtype of a ggml type id; `None` for removed or unknown ids, which are refused
    /// rather than guessed.
    pub fn from_ggml_id(id: u32) -> Option<Self> {
        let element = match id {
            0 => Some(ElementType::F32),
            1 => Some(ElementType::F16),
            24 => Some(ElementType::I8),
            25 => Some(ElementType::I16),
            26 => Some(ElementType::I32),
            27 => Some(ElementType::I64),
            28 => Some(ElementType::F64),
            30 => Some(ElementType::Bf16),
            _ => None,
        };
        element
            .map(Self::Element)
            .or_else(|| GgmlType::from_id(id).map(Self::Ggml))
    }
}

/// How a tensor's shape maps to its bytes (§3.3 tensor index: strides/layout).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TensorLayout {
    /// Contiguous, outermost dimension first (safetensors, "C" order).
    RowMajor,
    /// Contiguous, innermost dimension first, with block types blocked along it (GGUF).
    GgmlInnermostFirst,
}

/// Why a shape does not describe a whole number of bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShapeError {
    /// The element, bit or byte count overflows 64 bits.
    Overflow,
    /// Sub-byte elements that do not fill whole bytes.
    NotWholeBytes,
    /// The innermost dimension is not a multiple of the block size.
    PartialBlock { block_elements: u64 },
    /// A block type outside the GGML layout.
    LayoutMismatch,
}

impl fmt::Display for ShapeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow => f.write_str("the tensor's size overflows 64 bits"),
            Self::NotWholeBytes => f.write_str("the tensor does not fill whole bytes"),
            Self::PartialBlock { block_elements } => write!(
                f,
                "the innermost dimension is not a multiple of the {block_elements}-element block"
            ),
            Self::LayoutMismatch => f.write_str("a block type needs the GGML layout"),
        }
    }
}

impl std::error::Error for ShapeError {}

/// Number of elements of `shape`; a zero dimension makes an empty tensor.
pub fn element_count(shape: &[u64]) -> Result<u64, ShapeError> {
    if shape.contains(&0) {
        return Ok(0);
    }
    shape.iter().try_fold(1u64, |count, &dimension| {
        count.checked_mul(dimension).ok_or(ShapeError::Overflow)
    })
}

/// The true length in bytes of a tensor (§3.3 tensor index: true lengths), refusing
/// overflow, partial bytes and partial blocks.
pub fn tensor_bytes(
    dtype: TensorDtype,
    layout: TensorLayout,
    shape: &[u64],
) -> Result<u64, ShapeError> {
    match dtype {
        TensorDtype::Element(element) => {
            let bits = element_count(shape)?
                .checked_mul(element.bits())
                .ok_or(ShapeError::Overflow)?;
            if bits % 8 != 0 {
                return Err(ShapeError::NotWholeBytes);
            }
            Ok(bits / 8)
        }
        TensorDtype::Ggml(ggml) => {
            if layout != TensorLayout::GgmlInnermostFirst {
                return Err(ShapeError::LayoutMismatch);
            }
            let (innermost, rest) = match shape.split_first() {
                Some((innermost, rest)) => (*innermost, rest),
                None => (1, &[][..]),
            };
            if innermost % ggml.block_elements() != 0 {
                return Err(ShapeError::PartialBlock {
                    block_elements: ggml.block_elements(),
                });
            }
            (innermost / ggml.block_elements())
                .checked_mul(ggml.block_bytes())
                .and_then(|row_bytes| row_bytes.checked_mul(element_count(rest).ok()?))
                .ok_or(ShapeError::Overflow)
        }
    }
}
