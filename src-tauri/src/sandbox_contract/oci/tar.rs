//! A strict streaming tar reader for layer streams (VM-W33 "malicious archive paths,
//! links, metadata ... corrupt layers"; §5.2 line 2073 archive extraction is an attack
//! surface).
//!
//! It reads POSIX ustar and GNU headers block by block, checks every header checksum and
//! numeric field, and accepts only regular files, hard links, symbolic links, directories,
//! devices and FIFOs (devices and FIFOs are then refused by V05), plus local PAX extended
//! headers and GNU long names as metadata. Global PAX headers, sparse files and every other
//! entry type are refused. PAX records are bounded and allowlisted, and the only extended
//! attributes accepted are `user.*`; security, trusted and system attributes (file
//! capabilities, overlay markers, ACLs) are refused. Data padding must be zero, the archive
//! must end with two zero blocks, and anything after them must be zero padding too.
//!
//! Names come out as untrusted text; the caller passes them through V05's checks.

use std::collections::BTreeMap;
use std::fmt;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

use super::digest::OciDigest;
use super::layer::LayerRefusal;
use super::limits::{bounded_text, len_u64, ImportLimits};
use crate::sandbox_contract::files::MAX_NAME_BYTES;

const BLOCK: usize = 512;
const BLOCK_BYTES: u64 = 512;

/// Why a tar stream was refused. Offsets are bytes into the expanded stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum TarRefusal {
    /// The stream ended inside a header, inside data or before the end-of-archive blocks.
    Truncated {
        offset_bytes: u64,
    },
    BadChecksum {
        offset_bytes: u64,
        stored: Option<u64>,
        computed: u64,
    },
    /// Neither the POSIX ustar nor the GNU magic.
    UnsupportedFormat {
        offset_bytes: u64,
    },
    MalformedField {
        offset_bytes: u64,
        field: &'static str,
    },
    /// Global PAX headers, sparse and contiguous files, volume labels and every other type
    /// this reader does not accept.
    UnsupportedEntryType {
        offset_bytes: u64,
        flag: u8,
    },
    NonUtf8 {
        offset_bytes: u64,
        field: &'static str,
    },
    /// Two extended headers of one kind before one entry, or one before the end.
    DanglingMetadata {
        offset_bytes: u64,
    },
    /// A PAX path and a GNU long name, or a PAX linkpath and a GNU long link, together.
    ConflictingNames {
        offset_bytes: u64,
    },
    MetadataTooLarge {
        offset_bytes: u64,
        size_bytes: u64,
        limit_bytes: u64,
    },
    PaxMalformed {
        offset_bytes: u64,
    },
    PaxTooManyRecords {
        offset_bytes: u64,
        limit: usize,
    },
    PaxDuplicateKey {
        offset_bytes: u64,
        key: String,
    },
    PaxKeyNotAllowed {
        offset_bytes: u64,
        key: String,
    },
    /// Only `user.*` extended attributes are accepted.
    XattrNotAllowed {
        offset_bytes: u64,
        name: String,
    },
    TooManyXattrs {
        offset_bytes: u64,
        limit: usize,
    },
    XattrTooLarge {
        offset_bytes: u64,
        bytes: usize,
        limit: usize,
    },
    /// A non-regular entry with data.
    DataOnNonFile {
        offset_bytes: u64,
        size_bytes: u64,
    },
    NonZeroPadding {
        offset_bytes: u64,
    },
    /// One zero block followed by a header.
    MalformedEnd {
        offset_bytes: u64,
    },
    /// Non-zero bytes after the end-of-archive blocks.
    TrailingGarbage {
        offset_bytes: u64,
    },
}

impl fmt::Display for TarRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { offset_bytes } => write!(f, "the tar stream ends at {offset_bytes}"),
            Self::BadChecksum {
                offset_bytes,
                stored,
                computed,
            } => write!(
                f,
                "header at {offset_bytes}: checksum {stored:?} stored, {computed} computed"
            ),
            Self::UnsupportedFormat { offset_bytes } => {
                write!(f, "header at {offset_bytes} is neither ustar nor GNU")
            }
            Self::MalformedField {
                offset_bytes,
                field,
            } => write!(f, "header at {offset_bytes}: malformed {field}"),
            Self::UnsupportedEntryType { offset_bytes, flag } => write!(
                f,
                "header at {offset_bytes}: entry type {:?} is refused",
                char::from(*flag)
            ),
            Self::NonUtf8 {
                offset_bytes,
                field,
            } => write!(f, "header at {offset_bytes}: {field} is not UTF-8"),
            Self::DanglingMetadata { offset_bytes } => {
                write!(f, "extended header at {offset_bytes} has no single entry")
            }
            Self::ConflictingNames { offset_bytes } => {
                write!(f, "header at {offset_bytes} names its path twice")
            }
            Self::MetadataTooLarge {
                offset_bytes,
                size_bytes,
                limit_bytes,
            } => write!(
                f,
                "extended header at {offset_bytes} is {size_bytes} bytes; at most {limit_bytes}"
            ),
            Self::PaxMalformed { offset_bytes } => {
                write!(f, "PAX header at {offset_bytes} is malformed")
            }
            Self::PaxTooManyRecords {
                offset_bytes,
                limit,
            } => write!(
                f,
                "PAX header at {offset_bytes} has more than {limit} records"
            ),
            Self::PaxDuplicateKey { offset_bytes, key } => {
                write!(f, "PAX header at {offset_bytes} repeats {key:?}")
            }
            Self::PaxKeyNotAllowed { offset_bytes, key } => {
                write!(f, "PAX header at {offset_bytes}: {key:?} is not allowed")
            }
            Self::XattrNotAllowed { offset_bytes, name } => {
                write!(
                    f,
                    "PAX header at {offset_bytes}: attribute {name:?} is not allowed"
                )
            }
            Self::TooManyXattrs {
                offset_bytes,
                limit,
            } => write!(
                f,
                "PAX header at {offset_bytes}: more than {limit} attributes"
            ),
            Self::XattrTooLarge {
                offset_bytes,
                bytes,
                limit,
            } => write!(
                f,
                "PAX header at {offset_bytes}: a {bytes}-byte attribute; at most {limit}"
            ),
            Self::DataOnNonFile {
                offset_bytes,
                size_bytes,
            } => write!(
                f,
                "header at {offset_bytes} declares {size_bytes} bytes on a non-regular entry"
            ),
            Self::NonZeroPadding { offset_bytes } => {
                write!(f, "non-zero padding at {offset_bytes}")
            }
            Self::MalformedEnd { offset_bytes } => {
                write!(f, "a lone zero block at {offset_bytes}")
            }
            Self::TrailingGarbage { offset_bytes } => {
                write!(f, "data after the end of the archive at {offset_bytes}")
            }
        }
    }
}

impl std::error::Error for TarRefusal {}

/// A stream of expanded layer bytes that refuses with a typed reason, such as a limit.
pub(crate) trait ByteSource {
    /// Reads into `buffer`; zero means the stream ended.
    fn read(&mut self, buffer: &mut [u8]) -> Result<usize, LayerRefusal>;
}

/// What a tar entry is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TarKind {
    Regular,
    HardLink,
    Symlink,
    Directory,
    CharacterDevice,
    BlockDevice,
    Fifo,
}

impl TarKind {
    /// The `S_IFMT` bits some writers store in the mode field for this kind.
    fn type_bits(self) -> u64 {
        match self {
            Self::Regular | Self::HardLink => 0o100_000,
            Self::Symlink => 0o120_000,
            Self::Directory => 0o040_000,
            Self::CharacterDevice => 0o020_000,
            Self::BlockDevice => 0o060_000,
            Self::Fifo => 0o010_000,
        }
    }
}

/// One entry's header, its extended metadata applied.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TarEntry {
    /// Position among real entries, metadata headers not counted.
    pub index: usize,
    pub header_offset_bytes: u64,
    pub name: String,
    pub kind: TarKind,
    /// Permission bits, `0o7777` at most.
    pub mode: u32,
    pub uid: u64,
    pub gid: u64,
    pub size_bytes: u64,
    pub link_target: Option<String>,
    pub xattrs: BTreeMap<String, Vec<u8>>,
}

#[derive(Default)]
struct Pax {
    path: Option<String>,
    linkpath: Option<String>,
    size: Option<u64>,
    uid: Option<u64>,
    gid: Option<u64>,
    xattrs: BTreeMap<String, Vec<u8>>,
}

#[derive(Default)]
struct Pending {
    pax: Option<Pax>,
    long_name: Option<String>,
    long_link: Option<String>,
    first_offset_bytes: Option<u64>,
}

impl Pending {
    fn is_empty(&self) -> bool {
        self.pax.is_none() && self.long_name.is_none() && self.long_link.is_none()
    }
}

/// Reads one layer's tar stream entry by entry.
pub(crate) struct TarReader<'a, S: ByteSource> {
    source: &'a mut S,
    limits: &'a ImportLimits,
    offset_bytes: u64,
    entries: usize,
    unread_data: Option<u64>,
    buffer: Vec<u8>,
}

fn tar(refusal: TarRefusal) -> LayerRefusal {
    LayerRefusal::Tar { refusal }
}

fn field(block: &[u8; BLOCK], start: usize, length: usize) -> &[u8] {
    block
        .get(start..start.saturating_add(length))
        .unwrap_or(&[])
}

fn c_string(bytes: &[u8]) -> &[u8] {
    match bytes.iter().position(|byte| *byte == 0) {
        Some(end) => bytes.get(..end).unwrap_or(&[]),
        None => bytes,
    }
}

/// An octal or GNU base-256 number; `None` when malformed, negative or too large.
fn parse_numeric(bytes: &[u8]) -> Option<u64> {
    let first = *bytes.first()?;
    if first & 0x80 != 0 {
        if first & 0x40 != 0 {
            return None;
        }
        let mut value = u64::from(first & 0x3f);
        for byte in bytes.get(1..)? {
            value = value.checked_mul(256)?.checked_add(u64::from(*byte))?;
        }
        return Some(value);
    }
    let start = bytes.iter().position(|byte| *byte != b' ')?;
    let rest = bytes.get(start..)?;
    let digits = rest
        .iter()
        .position(|byte| !(b'0'..=b'7').contains(byte))
        .unwrap_or(rest.len());
    if digits == 0 {
        return None;
    }
    if !rest
        .get(digits..)?
        .iter()
        .all(|byte| *byte == 0 || *byte == b' ')
    {
        return None;
    }
    rest.get(..digits)?.iter().try_fold(0u64, |value, byte| {
        value
            .checked_mul(8)?
            .checked_add(u64::from(byte.checked_sub(b'0')?))
    })
}

fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    bytes.iter().try_fold(0u64, |value, byte| {
        value
            .checked_mul(10)?
            .checked_add(u64::from(byte.checked_sub(b'0')?))
    })
}

/// `digits` or `digits.digits`, the PAX time form; negative times are refused.
fn is_pax_time(bytes: &[u8]) -> bool {
    let mut parts = bytes.splitn(2, |byte| *byte == b'.');
    let whole = parts.next().unwrap_or(&[]);
    let fraction = parts.next();
    parse_decimal(whole).is_some() && fraction.is_none_or(|digits| parse_decimal(digits).is_some())
}

fn padding_bytes(size_bytes: u64) -> u64 {
    BLOCK_BYTES.saturating_sub(size_bytes % BLOCK_BYTES) % BLOCK_BYTES
}

impl<'a, S: ByteSource> TarReader<'a, S> {
    pub(crate) fn new(source: &'a mut S, limits: &'a ImportLimits) -> Self {
        Self {
            source,
            limits,
            offset_bytes: 0,
            entries: 0,
            unread_data: None,
            buffer: vec![0u8; 64 << 10],
        }
    }

    fn read_exact(&mut self, buffer: &mut [u8]) -> Result<(), LayerRefusal> {
        let mut filled = 0usize;
        while filled < buffer.len() {
            let rest = buffer.get_mut(filled..).unwrap_or(&mut []);
            let read = self.source.read(rest)?;
            if read == 0 {
                return Err(tar(TarRefusal::Truncated {
                    offset_bytes: self.offset_bytes,
                }));
            }
            filled = filled.saturating_add(read);
            self.offset_bytes = self.offset_bytes.saturating_add(len_u64(read));
        }
        Ok(())
    }

    fn read_block(&mut self) -> Result<[u8; BLOCK], LayerRefusal> {
        let mut block = [0u8; BLOCK];
        self.read_exact(&mut block)?;
        Ok(block)
    }

    /// Reads `size_bytes` of data, handing each chunk to `sink`, then checks the padding.
    fn read_data(
        &mut self,
        size_bytes: u64,
        sink: &mut dyn FnMut(&[u8]),
    ) -> Result<(), LayerRefusal> {
        let mut buffer = std::mem::take(&mut self.buffer);
        if buffer.is_empty() {
            buffer = vec![0u8; 64 << 10];
        }
        let result = self.read_data_with(&mut buffer, size_bytes, sink);
        self.buffer = buffer;
        result
    }

    fn read_data_with(
        &mut self,
        buffer: &mut [u8],
        size_bytes: u64,
        sink: &mut dyn FnMut(&[u8]),
    ) -> Result<(), LayerRefusal> {
        let mut remaining = size_bytes;
        while remaining > 0 {
            let take = usize::try_from(remaining.min(len_u64(buffer.len()))).unwrap_or(BLOCK);
            let chunk = buffer.get_mut(..take).unwrap_or(&mut []);
            self.read_exact(chunk)?;
            sink(chunk);
            remaining = remaining.saturating_sub(len_u64(take));
        }
        let padding = usize::try_from(padding_bytes(size_bytes)).unwrap_or(0);
        let offset_bytes = self.offset_bytes;
        let pad = buffer.get_mut(..padding).unwrap_or(&mut []);
        self.read_exact(pad)?;
        if pad.iter().any(|byte| *byte != 0) {
            return Err(tar(TarRefusal::NonZeroPadding { offset_bytes }));
        }
        Ok(())
    }

    /// Reads the data of the entry last returned by [`TarReader::next_entry`]: its sha256
    /// digest and the offset of its first byte in the expanded stream.
    pub(crate) fn entry_data(&mut self) -> Result<(OciDigest, u64), LayerRefusal> {
        let size_bytes = self.unread_data.take().unwrap_or(0);
        let data_offset_bytes = self.offset_bytes;
        let mut hasher = Sha256::new();
        self.read_data(size_bytes, &mut |chunk| hasher.update(chunk))?;
        Ok((OciDigest::from_hasher(hasher), data_offset_bytes))
    }

    fn read_metadata(
        &mut self,
        header_offset: u64,
        size_bytes: u64,
        limit_bytes: u64,
    ) -> Result<Vec<u8>, LayerRefusal> {
        if size_bytes > limit_bytes {
            return Err(tar(TarRefusal::MetadataTooLarge {
                offset_bytes: header_offset,
                size_bytes,
                limit_bytes,
            }));
        }
        let mut data = Vec::new();
        self.read_data(size_bytes, &mut |chunk| data.extend_from_slice(chunk))?;
        Ok(data)
    }

    /// The next entry, or `None` after the end-of-archive blocks and zero padding.
    pub(crate) fn next_entry(&mut self) -> Result<Option<TarEntry>, LayerRefusal> {
        if self.unread_data.is_some() {
            self.entry_data()?;
        }
        let mut pending = Pending::default();
        loop {
            let header_offset = self.offset_bytes;
            let block = self.read_block()?;
            if block.iter().all(|byte| *byte == 0) {
                if !pending.is_empty() {
                    return Err(tar(TarRefusal::DanglingMetadata {
                        offset_bytes: pending.first_offset_bytes.unwrap_or(header_offset),
                    }));
                }
                self.finish(header_offset)?;
                return Ok(None);
            }
            let stored = parse_numeric(field(&block, 148, 8));
            let computed = block
                .iter()
                .enumerate()
                .map(|(position, byte)| {
                    if (148..156).contains(&position) {
                        u64::from(b' ')
                    } else {
                        u64::from(*byte)
                    }
                })
                .sum::<u64>();
            if stored != Some(computed) {
                return Err(tar(TarRefusal::BadChecksum {
                    offset_bytes: header_offset,
                    stored,
                    computed,
                }));
            }
            let posix = match (field(&block, 257, 6), field(&block, 263, 2)) {
                (b"ustar\0", b"00") => true,
                (b"ustar ", b" \0") => false,
                _ => {
                    return Err(tar(TarRefusal::UnsupportedFormat {
                        offset_bytes: header_offset,
                    }))
                }
            };
            let malformed = |field: &'static str| {
                tar(TarRefusal::MalformedField {
                    offset_bytes: header_offset,
                    field,
                })
            };
            let size_bytes =
                parse_numeric(field(&block, 124, 12)).ok_or_else(|| malformed("size"))?;
            let flag = field(&block, 156, 1).first().copied().unwrap_or(0);
            let kind = match flag {
                b'0' | 0 => TarKind::Regular,
                b'1' => TarKind::HardLink,
                b'2' => TarKind::Symlink,
                b'3' => TarKind::CharacterDevice,
                b'4' => TarKind::BlockDevice,
                b'5' => TarKind::Directory,
                b'6' => TarKind::Fifo,
                b'x' | b'L' | b'K' => {
                    pending.first_offset_bytes.get_or_insert(header_offset);
                    self.read_extension(flag, header_offset, size_bytes, &mut pending)?;
                    continue;
                }
                other => {
                    return Err(tar(TarRefusal::UnsupportedEntryType {
                        offset_bytes: header_offset,
                        flag: other,
                    }))
                }
            };
            return self
                .finish_entry(&block, header_offset, posix, kind, size_bytes, pending)
                .map(Some);
        }
    }

    fn read_extension(
        &mut self,
        flag: u8,
        header_offset: u64,
        size_bytes: u64,
        pending: &mut Pending,
    ) -> Result<(), LayerRefusal> {
        let dangling = tar(TarRefusal::DanglingMetadata {
            offset_bytes: header_offset,
        });
        match flag {
            b'x' => {
                if pending.pax.is_some() {
                    return Err(dangling);
                }
                let data =
                    self.read_metadata(header_offset, size_bytes, self.limits.max_pax_bytes)?;
                pending.pax = Some(self.parse_pax(header_offset, &data)?);
            }
            _ => {
                let slot = if flag == b'L' {
                    &pending.long_name
                } else {
                    &pending.long_link
                };
                if slot.is_some() {
                    return Err(dangling);
                }
                let limit = len_u64(MAX_NAME_BYTES).saturating_add(1);
                let data = self.read_metadata(header_offset, size_bytes, limit)?;
                let text = std::str::from_utf8(c_string(&data))
                    .map_err(|_| {
                        tar(TarRefusal::NonUtf8 {
                            offset_bytes: header_offset,
                            field: "long name",
                        })
                    })?
                    .to_owned();
                if flag == b'L' {
                    pending.long_name = Some(text);
                } else {
                    pending.long_link = Some(text);
                }
            }
        }
        Ok(())
    }

    fn parse_pax(&self, offset_bytes: u64, data: &[u8]) -> Result<Pax, LayerRefusal> {
        let malformed = || tar(TarRefusal::PaxMalformed { offset_bytes });
        let mut pax = Pax::default();
        let mut keys = std::collections::BTreeSet::new();
        let mut position = 0usize;
        while position < data.len() {
            let rest = data.get(position..).ok_or_else(malformed)?;
            let space = rest
                .iter()
                .position(|byte| *byte == b' ')
                .ok_or_else(malformed)?;
            let length_text = rest.get(..space).ok_or_else(malformed)?;
            if length_text.first() == Some(&b'0') {
                return Err(malformed());
            }
            let length = parse_decimal(length_text)
                .and_then(|length| usize::try_from(length).ok())
                .ok_or_else(malformed)?;
            if length <= space.saturating_add(1) || length > rest.len() {
                return Err(malformed());
            }
            let record = rest.get(..length).ok_or_else(malformed)?;
            if record.last() != Some(&b'\n') {
                return Err(malformed());
            }
            let pair = record
                .get(space.saturating_add(1)..length.saturating_sub(1))
                .ok_or_else(malformed)?;
            let equals = pair
                .iter()
                .position(|byte| *byte == b'=')
                .ok_or_else(malformed)?;
            let key = std::str::from_utf8(pair.get(..equals).ok_or_else(malformed)?)
                .map_err(|_| malformed())?;
            let value = pair.get(equals.saturating_add(1)..).ok_or_else(malformed)?;
            if key.is_empty() {
                return Err(malformed());
            }
            if keys.len() >= self.limits.max_pax_records {
                return Err(tar(TarRefusal::PaxTooManyRecords {
                    offset_bytes,
                    limit: self.limits.max_pax_records,
                }));
            }
            if !keys.insert(key.to_owned()) {
                return Err(tar(TarRefusal::PaxDuplicateKey {
                    offset_bytes,
                    key: bounded_text(key, 64),
                }));
            }
            self.apply_pax_record(offset_bytes, key, value, &mut pax)?;
            position = position.saturating_add(length);
        }
        Ok(pax)
    }

    fn apply_pax_record(
        &self,
        offset_bytes: u64,
        key: &str,
        value: &[u8],
        pax: &mut Pax,
    ) -> Result<(), LayerRefusal> {
        let malformed = || tar(TarRefusal::PaxMalformed { offset_bytes });
        let text = || {
            std::str::from_utf8(value).map(str::to_owned).map_err(|_| {
                tar(TarRefusal::NonUtf8 {
                    offset_bytes,
                    field: "PAX value",
                })
            })
        };
        match key {
            "path" => pax.path = Some(text()?),
            "linkpath" => pax.linkpath = Some(text()?),
            "size" => pax.size = Some(parse_decimal(value).ok_or_else(malformed)?),
            "uid" => pax.uid = Some(parse_decimal(value).ok_or_else(malformed)?),
            "gid" => pax.gid = Some(parse_decimal(value).ok_or_else(malformed)?),
            "mtime" | "atime" | "ctime" => {
                if !is_pax_time(value) {
                    return Err(malformed());
                }
            }
            "uname" | "gname" => {
                text()?;
            }
            _ => {
                let Some(name) = key.strip_prefix("SCHILY.xattr.") else {
                    return Err(tar(TarRefusal::PaxKeyNotAllowed {
                        offset_bytes,
                        key: bounded_text(key, 64),
                    }));
                };
                let allowed =
                    name.len() > "user.".len() && name.len() <= 255 && name.starts_with("user.");
                if !allowed {
                    return Err(tar(TarRefusal::XattrNotAllowed {
                        offset_bytes,
                        name: bounded_text(name, 64),
                    }));
                }
                if pax.xattrs.len() >= self.limits.max_xattrs_per_entry {
                    return Err(tar(TarRefusal::TooManyXattrs {
                        offset_bytes,
                        limit: self.limits.max_xattrs_per_entry,
                    }));
                }
                if value.len() > self.limits.max_xattr_value_bytes {
                    return Err(tar(TarRefusal::XattrTooLarge {
                        offset_bytes,
                        bytes: value.len(),
                        limit: self.limits.max_xattr_value_bytes,
                    }));
                }
                pax.xattrs.insert(name.to_owned(), value.to_vec());
            }
        }
        Ok(())
    }

    fn finish_entry(
        &mut self,
        block: &[u8; BLOCK],
        header_offset: u64,
        posix: bool,
        kind: TarKind,
        header_size_bytes: u64,
        pending: Pending,
    ) -> Result<TarEntry, LayerRefusal> {
        let malformed = |field: &'static str| {
            tar(TarRefusal::MalformedField {
                offset_bytes: header_offset,
                field,
            })
        };
        let utf8 = |bytes: &[u8], field: &'static str| {
            std::str::from_utf8(bytes).map(str::to_owned).map_err(|_| {
                tar(TarRefusal::NonUtf8 {
                    offset_bytes: header_offset,
                    field,
                })
            })
        };
        let conflict = tar(TarRefusal::ConflictingNames {
            offset_bytes: header_offset,
        });
        let pax = pending.pax.unwrap_or_default();
        let name = match (pax.path, pending.long_name) {
            (Some(_), Some(_)) => return Err(conflict),
            (Some(path), None) | (None, Some(path)) => path,
            (None, None) => {
                let base = utf8(c_string(field(block, 0, 100)), "name")?;
                let prefix = if posix {
                    utf8(c_string(field(block, 345, 155)), "prefix")?
                } else {
                    String::new()
                };
                if prefix.is_empty() {
                    base
                } else {
                    format!("{prefix}/{base}")
                }
            }
        };
        let link = match (pax.linkpath, pending.long_link) {
            (Some(_), Some(_)) => return Err(conflict),
            (Some(link), None) | (None, Some(link)) => link,
            (None, None) => utf8(c_string(field(block, 157, 100)), "linkname")?,
        };
        let is_link = matches!(kind, TarKind::Symlink | TarKind::HardLink);
        let link_target = match (is_link, link.is_empty()) {
            (true, false) => Some(link),
            (false, true) => None,
            _ => return Err(malformed("linkname")),
        };
        let mode_field = parse_numeric(field(block, 100, 8)).ok_or_else(|| malformed("mode"))?;
        let high_bits = mode_field & !0o7777;
        if high_bits != 0 && high_bits != kind.type_bits() {
            return Err(malformed("mode"));
        }
        let mode = u32::try_from(mode_field & 0o7777).map_err(|_| malformed("mode"))?;
        parse_numeric(field(block, 136, 12)).ok_or_else(|| malformed("mtime"))?;
        let uid = match pax.uid {
            Some(uid) => uid,
            None => parse_numeric(field(block, 108, 8)).ok_or_else(|| malformed("uid"))?,
        };
        let gid = match pax.gid {
            Some(gid) => gid,
            None => parse_numeric(field(block, 116, 8)).ok_or_else(|| malformed("gid"))?,
        };
        let size_bytes = pax.size.unwrap_or(header_size_bytes);
        if kind != TarKind::Regular && size_bytes != 0 {
            return Err(tar(TarRefusal::DataOnNonFile {
                offset_bytes: header_offset,
                size_bytes,
            }));
        }
        let index = self.entries;
        self.entries = self.entries.saturating_add(1);
        self.unread_data = Some(size_bytes);
        Ok(TarEntry {
            index,
            header_offset_bytes: header_offset,
            name,
            kind,
            mode,
            uid,
            gid,
            size_bytes,
            link_target,
            xattrs: pax.xattrs,
        })
    }

    /// After the first zero block: the second must be zero, and so must everything after.
    fn finish(&mut self, first_zero_offset: u64) -> Result<(), LayerRefusal> {
        let second = self.read_block()?;
        if second.iter().any(|byte| *byte != 0) {
            return Err(tar(TarRefusal::MalformedEnd {
                offset_bytes: first_zero_offset,
            }));
        }
        let mut buffer = vec![0u8; 16 << 10];
        loop {
            let offset_bytes = self.offset_bytes;
            let read = self.source.read(&mut buffer)?;
            if read == 0 {
                return Ok(());
            }
            let chunk = buffer.get(..read).unwrap_or(&[]);
            if let Some(position) = chunk.iter().position(|byte| *byte != 0) {
                return Err(tar(TarRefusal::TrailingGarbage {
                    offset_bytes: offset_bytes.saturating_add(len_u64(position)),
                }));
            }
            self.offset_bytes = self.offset_bytes.saturating_add(len_u64(read));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numeric_fields_are_strict() {
        assert_eq!(parse_numeric(b"0000644\0"), Some(0o644));
        assert_eq!(parse_numeric(b"  644 \0"), Some(0o644));
        assert_eq!(parse_numeric(b"00000000017\0"), Some(15));
        assert_eq!(parse_numeric(b"\0\0\0\0"), None);
        assert_eq!(parse_numeric(b"0008\0"), None);
        assert_eq!(parse_numeric(b"12 3\0"), None);
        assert_eq!(parse_numeric(b"-1\0"), None);
        // GNU base-256: 0x80 then a big-endian value.
        assert_eq!(
            parse_numeric(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0]),
            Some(256)
        );
        assert_eq!(parse_numeric(&[0xff; 12]), None);
        assert_eq!(
            parse_numeric(&[0x80, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
            None
        );
        assert_eq!(parse_numeric(b"77777777777777777777777"), None);
    }

    #[test]
    fn pax_times_and_decimals_are_strict() {
        assert!(is_pax_time(b"1700000000"));
        assert!(is_pax_time(b"1700000000.123456789"));
        assert!(!is_pax_time(b"-1"));
        assert!(!is_pax_time(b"1."));
        assert!(!is_pax_time(b"1.2.3"));
        assert_eq!(parse_decimal(b"42"), Some(42));
        assert_eq!(parse_decimal(b""), None);
        assert_eq!(parse_decimal(b"4 2"), None);
        assert_eq!(parse_decimal(b"99999999999999999999999"), None);
    }

    #[test]
    fn padding_rounds_to_the_next_block() {
        assert_eq!(padding_bytes(0), 0);
        assert_eq!(padding_bytes(1), 511);
        assert_eq!(padding_bytes(512), 0);
        assert_eq!(padding_bytes(513), 511);
    }
}
