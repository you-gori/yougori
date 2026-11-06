//! A strict reader and writer of the SDDL subset that states a named pipe's owner, DACL
//! and mandatory label (M06 carry-forward: "restrict transport writers"; §3.2 line 2073:
//! "Bind the host's channel to the VM object it launched"; VM-R64 line 2929: "OS
//! permissions"). The writer renders a [`SecurityDescriptor`] the way Windows renders one
//! read back from an object; the reader accepts exactly this grammar and refuses
//! everything else with the byte offset where it stopped:
//!
//! ```text
//! descriptor := ["O:" sid] ["G:" sid] ["D:" acl] ["S:" acl]     at least one, in this order
//! acl        := flags ["NO_ACCESS_CONTROL"] ace*                 flags: P, AI, AR, each once
//! ace        := "(" type ";" ace-flags ";" rights ";" ";" ";" sid ")"
//! type       := "A" | "D" (DACL only) | "ML" (SACL only)
//! ace-flags  := { OI | CI | NP | IO | ID }, each once
//! rights     := "0x" lowercase hex without leading zeros | aliases, each once
//! sid        := "S-1-" authority { "-" sub-authority } | a well-known alias
//! ```
//!
//! No whitespace, no lowercase keyword, no object or conditional ACE, no audit ACE, no
//! alias outside the closed tables below, no hexadecimal identifier authority and nothing
//! after the last section. Rights and SIDs are compared by value, so `FA` and `0x1f01ff`,
//! or `SY` and `S-1-5-18`, read as the same.

use std::fmt;

use serde::{Serialize, Serializer};

/// The longest descriptor text read.
pub const MAX_SDDL_BYTES: usize = 4_096;
/// ACEs read at most, both lists together.
pub const MAX_ACES: usize = 32;
/// Sub-authorities of one SID at most (`SID_MAX_SUB_AUTHORITIES`).
pub const MAX_SUB_AUTHORITIES: usize = 15;

/// The well-known SIDs SDDL names by a two-letter alias, as (alias, authority,
/// sub-authorities). Aliases that depend on the machine's domain (`DA`, `LA` and the
/// like) are not here and are refused.
const SID_ALIASES: [(&str, u32, &[u32]); 26] = [
    ("WD", 1, &[0]),
    ("CO", 3, &[0]),
    ("CG", 3, &[1]),
    ("OW", 3, &[4]),
    ("NU", 5, &[2]),
    ("IU", 5, &[4]),
    ("SU", 5, &[6]),
    ("AN", 5, &[7]),
    ("PS", 5, &[10]),
    ("AU", 5, &[11]),
    ("RC", 5, &[12]),
    ("SY", 5, &[18]),
    ("LS", 5, &[19]),
    ("NS", 5, &[20]),
    ("WR", 5, &[33]),
    ("BA", 5, &[32, 544]),
    ("BU", 5, &[32, 545]),
    ("BG", 5, &[32, 546]),
    ("PU", 5, &[32, 547]),
    ("BO", 5, &[32, 551]),
    ("AC", 15, &[2, 1]),
    ("LW", 16, &[4_096]),
    ("ME", 16, &[8_192]),
    ("MP", 16, &[8_448]),
    ("HI", 16, &[12_288]),
    ("SI", 16, &[16_384]),
];

/// Access-right aliases of allow and deny ACEs.
const RIGHT_ALIASES: [(&str, u32); 25] = [
    ("GA", 0x1000_0000),
    ("GR", 0x8000_0000),
    ("GW", 0x4000_0000),
    ("GX", 0x2000_0000),
    ("RC", 0x0002_0000),
    ("SD", 0x0001_0000),
    ("WD", 0x0004_0000),
    ("WO", 0x0008_0000),
    ("CC", 0x0000_0001),
    ("DC", 0x0000_0002),
    ("LC", 0x0000_0004),
    ("SW", 0x0000_0008),
    ("RP", 0x0000_0010),
    ("WP", 0x0000_0020),
    ("DT", 0x0000_0040),
    ("LO", 0x0000_0080),
    ("CR", 0x0000_0100),
    ("FA", 0x001f_01ff),
    ("FR", 0x0012_0089),
    ("FW", 0x0012_0116),
    ("FX", 0x0012_00a0),
    ("KA", 0x000f_003f),
    ("KR", 0x0002_0019),
    ("KW", 0x0002_0006),
    ("KX", 0x0002_0019),
];

/// The aliases the writer uses for a whole allow or deny mask; any other mask is written
/// in hexadecimal, as Windows does for a mask no single alias names.
const WHOLE_MASK_ALIASES: [&str; 8] = ["FA", "FR", "FW", "FX", "GA", "GR", "GW", "GX"];

/// Mandatory-label policy aliases: no write up, no read up, no execute up.
const LABEL_ALIASES: [(&str, u32); 3] = [("NW", 0x1), ("NR", 0x2), ("NX", 0x4)];

/// What was wrong, without where.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SddlErrorKind {
    Empty,
    TooLong,
    /// A byte outside printable ASCII, whitespace included.
    InvalidCharacter,
    /// Something other than the next expected token.
    UnexpectedToken,
    DuplicateSection,
    /// The sections are not in the order O, G, D, S.
    SectionOrder,
    DuplicateFlag,
    /// `NO_ACCESS_CONTROL` followed by ACEs.
    NullAclWithAces,
    TooManyAces,
    /// An ACE type outside A, D and ML (audit, object, callback and the rest).
    UnsupportedAceType,
    /// A label ACE in the DACL or an allow or deny ACE in the SACL.
    AceOutOfPlace,
    UnknownAceFlag,
    DuplicateAceFlag,
    EmptyRights,
    /// Hexadecimal rights that are not `0x` with one to eight lowercase digits and no
    /// leading zero.
    InvalidHexRights,
    UnknownRight,
    DuplicateRight,
    /// An object type or inherited object type GUID: object ACEs are not supported.
    ObjectAce,
    /// A seventh ACE field (resource attributes or a condition).
    ExtraAceField,
    UnterminatedAce,
    InvalidSid,
    UnknownSidAlias,
    TooManySubAuthorities,
}

impl SddlErrorKind {
    fn describe(self) -> &'static str {
        match self {
            Self::Empty => "the descriptor is empty",
            Self::TooLong => "the descriptor is longer than the limit",
            Self::InvalidCharacter => "a character outside printable ASCII",
            Self::UnexpectedToken => "an unexpected token",
            Self::DuplicateSection => "a section appears twice",
            Self::SectionOrder => "the sections are not in the order O, G, D, S",
            Self::DuplicateFlag => "an ACL flag appears twice",
            Self::NullAclWithAces => "NO_ACCESS_CONTROL is followed by ACEs",
            Self::TooManyAces => "more ACEs than the limit",
            Self::UnsupportedAceType => "an ACE type other than A, D and ML",
            Self::AceOutOfPlace => "a label ACE in the DACL or an access ACE in the SACL",
            Self::UnknownAceFlag => "an unknown ACE flag",
            Self::DuplicateAceFlag => "an ACE flag appears twice",
            Self::EmptyRights => "an ACE grants no rights field",
            Self::InvalidHexRights => "hexadecimal rights are not in canonical form",
            Self::UnknownRight => "an unknown rights alias",
            Self::DuplicateRight => "a rights alias appears twice",
            Self::ObjectAce => "an object ACE GUID",
            Self::ExtraAceField => "an ACE has a seventh field",
            Self::UnterminatedAce => "an ACE is not closed",
            Self::InvalidSid => "a SID is not in canonical form",
            Self::UnknownSidAlias => "an unknown SID alias",
            Self::TooManySubAuthorities => "a SID has more than 15 sub-authorities",
        }
    }
}

/// Why descriptor text was refused, and the byte offset where reading stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct SddlError {
    pub offset: usize,
    pub kind: SddlErrorKind,
}

impl fmt::Display for SddlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SDDL at byte {}: {}", self.offset, self.kind.describe())
    }
}

impl std::error::Error for SddlError {}

/// A security identifier with revision 1 and an identifier authority below 2^32, the only
/// kind SDDL writes in decimal.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Sid {
    authority: u32,
    sub_authorities: Vec<u32>,
}

impl Sid {
    /// A SID from its parts; refused beyond [`MAX_SUB_AUTHORITIES`].
    pub fn new(authority: u32, sub_authorities: &[u32]) -> Result<Self, SddlError> {
        if sub_authorities.len() > MAX_SUB_AUTHORITIES {
            return Err(SddlError {
                offset: 0,
                kind: SddlErrorKind::TooManySubAuthorities,
            });
        }
        Ok(Self {
            authority,
            sub_authorities: sub_authorities.to_vec(),
        })
    }

    /// Reads one SID, in string form or as an alias, and nothing else.
    pub fn parse(text: &str) -> Result<Self, SddlError> {
        let mut reader = Reader::new(text)?;
        let sid = reader.sid()?;
        if !reader.at_end() {
            return Err(reader.error(SddlErrorKind::UnexpectedToken));
        }
        Ok(sid)
    }

    /// `S-1-16-4096`, the low mandatory level (`LW`).
    pub fn low_mandatory_level() -> Self {
        Self {
            authority: 16,
            sub_authorities: vec![4_096],
        }
    }

    pub fn authority(&self) -> u32 {
        self.authority
    }

    pub fn sub_authorities(&self) -> &[u32] {
        &self.sub_authorities
    }

    /// The SDDL alias of a well-known SID.
    pub fn alias(&self) -> Option<&'static str> {
        SID_ALIASES
            .iter()
            .find(|(_, authority, subs)| {
                *authority == self.authority && *subs == self.sub_authorities.as_slice()
            })
            .map(|(alias, _, _)| *alias)
    }

    /// The token the writer uses: the alias of a well-known SID, otherwise the string
    /// form, as Windows renders a descriptor.
    pub fn sddl_token(&self) -> String {
        match self.alias() {
            Some(alias) => alias.to_owned(),
            None => self.to_string(),
        }
    }

    fn from_alias(alias: &str) -> Option<Self> {
        SID_ALIASES
            .iter()
            .find(|(name, _, _)| *name == alias)
            .map(|(_, authority, subs)| Self {
                authority: *authority,
                sub_authorities: subs.to_vec(),
            })
    }
}

/// The string form, `S-1-` followed by the authority and sub-authorities.
impl fmt::Display for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S-1-{}", self.authority)?;
        for sub in &self.sub_authorities {
            write!(f, "-{sub}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Sid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sid({self})")
    }
}

/// Written in its string form; a SID is never read from a record.
impl Serialize for Sid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

/// The ACE types read: access allowed, access denied and the mandatory label.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AceType {
    Allow,
    Deny,
    MandatoryLabel,
}

impl AceType {
    const fn token(self) -> &'static str {
        match self {
            Self::Allow => "A",
            Self::Deny => "D",
            Self::MandatoryLabel => "ML",
        }
    }
}

/// The inheritance flags of one ACE.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize)]
pub struct AceFlags {
    pub object_inherit: bool,
    pub container_inherit: bool,
    pub no_propagate: bool,
    pub inherit_only: bool,
    pub inherited: bool,
}

impl AceFlags {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    fn render(&self, out: &mut String) {
        for (set, token) in [
            (self.object_inherit, "OI"),
            (self.container_inherit, "CI"),
            (self.no_propagate, "NP"),
            (self.inherit_only, "IO"),
            (self.inherited, "ID"),
        ] {
            if set {
                out.push_str(token);
            }
        }
    }
}

/// One access-control entry.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct Ace {
    pub kind: AceType,
    pub flags: AceFlags,
    pub mask: u32,
    pub sid: Sid,
}

impl Ace {
    pub fn allow(mask: u32, sid: Sid) -> Self {
        Self {
            kind: AceType::Allow,
            flags: AceFlags::default(),
            mask,
            sid,
        }
    }

    pub fn label(mask: u32, sid: Sid) -> Self {
        Self {
            kind: AceType::MandatoryLabel,
            flags: AceFlags::default(),
            mask,
            sid,
        }
    }

    fn render(&self, out: &mut String) {
        out.push('(');
        out.push_str(self.kind.token());
        out.push(';');
        self.flags.render(out);
        out.push(';');
        out.push_str(&render_mask(self.kind, self.mask));
        out.push_str(";;;");
        out.push_str(&self.sid.sddl_token());
        out.push(')');
    }
}

impl fmt::Display for Ace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut text = String::new();
        self.render(&mut text);
        f.write_str(&text)
    }
}

fn render_mask(kind: AceType, mask: u32) -> String {
    match kind {
        AceType::MandatoryLabel => {
            let named: u32 = LABEL_ALIASES.iter().map(|(_, bits)| bits).sum();
            if mask != 0 && mask & !named == 0 {
                return LABEL_ALIASES
                    .iter()
                    .filter(|(_, bits)| mask & bits != 0)
                    .map(|(alias, _)| *alias)
                    .collect();
            }
        }
        AceType::Allow | AceType::Deny => {
            if let Some((alias, _)) = RIGHT_ALIASES
                .iter()
                .find(|(alias, bits)| *bits == mask && WHOLE_MASK_ALIASES.contains(alias))
            {
                return (*alias).to_owned();
            }
        }
    }
    format!("{mask:#x}")
}

/// The control flags of one ACL.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize)]
pub struct AclFlags {
    /// `P`: inheritable ACEs from the parent do not apply.
    pub protected: bool,
    /// `AI`.
    pub auto_inherited: bool,
    /// `AR`.
    pub auto_inherit_required: bool,
}

/// A DACL or SACL.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Acl {
    pub flags: AclFlags,
    /// `NO_ACCESS_CONTROL`: a null ACL, which grants every access when it is the DACL.
    pub null: bool,
    pub aces: Vec<Ace>,
}

impl Acl {
    fn render(&self, out: &mut String) {
        for (set, token) in [
            (self.flags.protected, "P"),
            (self.flags.auto_inherited, "AI"),
            (self.flags.auto_inherit_required, "AR"),
        ] {
            if set {
                out.push_str(token);
            }
        }
        if self.null {
            out.push_str("NO_ACCESS_CONTROL");
        }
        for ace in &self.aces {
            ace.render(out);
        }
    }
}

/// A security descriptor: owner, group, DACL and SACL, each possibly absent.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SecurityDescriptor {
    pub owner: Option<Sid>,
    pub group: Option<Sid>,
    pub dacl: Option<Acl>,
    pub sacl: Option<Acl>,
}

impl SecurityDescriptor {
    /// The SDDL text, in the form [`SecurityDescriptor::parse`] reads back to the same
    /// value.
    pub fn to_sddl(&self) -> String {
        let mut out = String::new();
        if let Some(owner) = &self.owner {
            out.push_str("O:");
            out.push_str(&owner.sddl_token());
        }
        if let Some(group) = &self.group {
            out.push_str("G:");
            out.push_str(&group.sddl_token());
        }
        if let Some(dacl) = &self.dacl {
            out.push_str("D:");
            dacl.render(&mut out);
        }
        if let Some(sacl) = &self.sacl {
            out.push_str("S:");
            sacl.render(&mut out);
        }
        out
    }

    /// Reads descriptor text strictly (see the module notes).
    pub fn parse(text: &str) -> Result<Self, SddlError> {
        let mut reader = Reader::new(text)?;
        let mut descriptor = Self::default();
        let mut last: Option<usize> = None;
        let mut aces = 0usize;
        while !reader.at_end() {
            let at = reader.position;
            let section = match reader.take_any(&["O:", "G:", "D:", "S:"]) {
                Some(index) => index,
                None => return Err(reader.error(SddlErrorKind::UnexpectedToken)),
            };
            match last {
                Some(previous) if previous == section => {
                    return Err(SddlError {
                        offset: at,
                        kind: SddlErrorKind::DuplicateSection,
                    })
                }
                Some(previous) if previous > section => {
                    return Err(SddlError {
                        offset: at,
                        kind: SddlErrorKind::SectionOrder,
                    })
                }
                _ => last = Some(section),
            }
            match section {
                0 => descriptor.owner = Some(reader.sid()?),
                1 => descriptor.group = Some(reader.sid()?),
                2 => descriptor.dacl = Some(reader.acl(false, &mut aces)?),
                _ => descriptor.sacl = Some(reader.acl(true, &mut aces)?),
            }
            if !reader.at_end() && !reader.at_section() {
                return Err(reader.error(SddlErrorKind::UnexpectedToken));
            }
        }
        if last.is_none() {
            return Err(reader.error(SddlErrorKind::Empty));
        }
        Ok(descriptor)
    }
}

/// A cursor over descriptor text, one linear pass with no recursion.
struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}

impl<'a> Reader<'a> {
    fn new(text: &'a str) -> Result<Self, SddlError> {
        let bytes = text.as_bytes();
        if bytes.is_empty() {
            return Err(SddlError {
                offset: 0,
                kind: SddlErrorKind::Empty,
            });
        }
        if bytes.len() > MAX_SDDL_BYTES {
            return Err(SddlError {
                offset: MAX_SDDL_BYTES,
                kind: SddlErrorKind::TooLong,
            });
        }
        if let Some(offset) = bytes.iter().position(|byte| !byte.is_ascii_graphic()) {
            return Err(SddlError {
                offset,
                kind: SddlErrorKind::InvalidCharacter,
            });
        }
        Ok(Self { bytes, position: 0 })
    }

    fn error(&self, kind: SddlErrorKind) -> SddlError {
        SddlError {
            offset: self.position,
            kind,
        }
    }

    fn at_end(&self) -> bool {
        self.position >= self.bytes.len()
    }

    fn rest(&self) -> &'a [u8] {
        self.bytes.get(self.position..).unwrap_or_default()
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.position).copied()
    }

    fn at_section(&self) -> bool {
        matches!(self.rest(), [b'O' | b'G' | b'D' | b'S', b':', ..])
    }

    /// Takes the first of `tokens` the text continues with; returns its index.
    fn take_any(&mut self, tokens: &[&str]) -> Option<usize> {
        let rest = self.rest();
        let (index, token) = tokens
            .iter()
            .enumerate()
            .find(|(_, token)| rest.starts_with(token.as_bytes()))?;
        self.position += token.len();
        Some(index)
    }

    /// Reads the SID that starts here: `S-` with the digits and hyphens after it, or a
    /// two-letter alias.
    fn sid(&mut self) -> Result<Sid, SddlError> {
        let start = self.position;
        let rest = self.rest();
        let length = if rest.starts_with(b"S-") {
            2 + rest
                .get(2..)
                .unwrap_or_default()
                .iter()
                .take_while(|byte| byte.is_ascii_digit() || **byte == b'-')
                .count()
        } else {
            rest.len().min(2)
        };
        self.position += length;
        sid_token(rest.get(..length).unwrap_or_default()).map_err(|kind| SddlError {
            offset: start,
            kind,
        })
    }

    fn acl(&mut self, system: bool, aces: &mut usize) -> Result<Acl, SddlError> {
        let mut acl = Acl::default();
        loop {
            let at = self.position;
            let slot = match self.take_any(&["P", "AI", "AR"]) {
                Some(0) => &mut acl.flags.protected,
                Some(1) => &mut acl.flags.auto_inherited,
                Some(2) => &mut acl.flags.auto_inherit_required,
                _ => break,
            };
            if *slot {
                return Err(SddlError {
                    offset: at,
                    kind: SddlErrorKind::DuplicateFlag,
                });
            }
            *slot = true;
        }
        if self.take_any(&["NO_ACCESS_CONTROL"]).is_some() {
            acl.null = true;
            if self.peek() == Some(b'(') {
                return Err(self.error(SddlErrorKind::NullAclWithAces));
            }
            return Ok(acl);
        }
        while self.peek() == Some(b'(') {
            if *aces >= MAX_ACES {
                return Err(self.error(SddlErrorKind::TooManyAces));
            }
            *aces += 1;
            acl.aces.push(self.ace(system)?);
        }
        Ok(acl)
    }

    /// One ACE: exactly six fields between the parentheses.
    fn ace(&mut self, system: bool) -> Result<Ace, SddlError> {
        self.position += 1;
        let start = self.position;
        let rest = self.rest();
        let Some(length) = rest.iter().position(|byte| *byte == b')') else {
            return Err(SddlError {
                offset: self.bytes.len(),
                kind: SddlErrorKind::UnterminatedAce,
            });
        };
        let body = std::str::from_utf8(rest.get(..length).unwrap_or_default()).unwrap_or("");
        let mut fields = Vec::with_capacity(6);
        let mut offset = start;
        for field in body.split(';') {
            fields.push((offset, field));
            offset += field.len() + 1;
        }
        let [kind, flags, rights, object, inherited_object, sid] = fields.as_slice() else {
            return Err(match fields.get(6) {
                Some((at, _)) => SddlError {
                    offset: at - 1,
                    kind: SddlErrorKind::ExtraAceField,
                },
                None => SddlError {
                    offset: start + length,
                    kind: SddlErrorKind::UnterminatedAce,
                },
            });
        };
        let fail = |(offset, _): &(usize, &str), kind| SddlError {
            offset: *offset,
            kind,
        };
        let ace_type = match kind.1 {
            "A" => AceType::Allow,
            "D" => AceType::Deny,
            "ML" => AceType::MandatoryLabel,
            _ => return Err(fail(kind, SddlErrorKind::UnsupportedAceType)),
        };
        if system != (ace_type == AceType::MandatoryLabel) {
            return Err(fail(kind, SddlErrorKind::AceOutOfPlace));
        }
        let ace_flags = parse_ace_flags(flags.1).map_err(|error| fail(flags, error))?;
        let mask = parse_rights(ace_type, rights.1).map_err(|error| fail(rights, error))?;
        for guid in [object, inherited_object] {
            if !guid.1.is_empty() {
                return Err(fail(guid, SddlErrorKind::ObjectAce));
            }
        }
        let sid = sid_token(sid.1.as_bytes()).map_err(|error| fail(sid, error))?;
        self.position = start + length + 1;
        Ok(Ace {
            kind: ace_type,
            flags: ace_flags,
            mask,
            sid,
        })
    }
}

/// One whole SID token: the string form or a known alias.
fn sid_token(token: &[u8]) -> Result<Sid, SddlErrorKind> {
    if token.starts_with(b"S-") {
        return parse_sid_string(token);
    }
    if token.len() != 2 || !token.iter().all(u8::is_ascii_uppercase) {
        return Err(SddlErrorKind::InvalidSid);
    }
    Sid::from_alias(std::str::from_utf8(token).unwrap_or("")).ok_or(SddlErrorKind::UnknownSidAlias)
}

/// `S-1-<authority>(-<sub-authority>)*`, every number decimal without a sign or a leading
/// zero, the authority and each sub-authority within 32 bits.
fn parse_sid_string(text: &[u8]) -> Result<Sid, SddlErrorKind> {
    let text = std::str::from_utf8(text).map_err(|_| SddlErrorKind::InvalidSid)?;
    let mut parts = text.split('-');
    if parts.next() != Some("S") || parts.next() != Some("1") {
        return Err(SddlErrorKind::InvalidSid);
    }
    let authority = parts
        .next()
        .ok_or(SddlErrorKind::InvalidSid)
        .and_then(decimal)?;
    let mut sub_authorities = Vec::new();
    for part in parts {
        if sub_authorities.len() == MAX_SUB_AUTHORITIES {
            return Err(SddlErrorKind::TooManySubAuthorities);
        }
        sub_authorities.push(decimal(part)?);
    }
    Ok(Sid {
        authority,
        sub_authorities,
    })
}

fn decimal(text: &str) -> Result<u32, SddlErrorKind> {
    let canonical = !text.is_empty()
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'));
    if !canonical {
        return Err(SddlErrorKind::InvalidSid);
    }
    text.parse().map_err(|_| SddlErrorKind::InvalidSid)
}

fn two_letter_tokens(text: &str) -> Option<Vec<&str>> {
    if text.len() % 2 != 0 {
        return None;
    }
    (0..text.len())
        .step_by(2)
        .map(|start| text.get(start..start + 2))
        .collect()
}

fn parse_ace_flags(text: &str) -> Result<AceFlags, SddlErrorKind> {
    let tokens = two_letter_tokens(text).ok_or(SddlErrorKind::UnknownAceFlag)?;
    let mut flags = AceFlags::default();
    for token in tokens {
        let slot = match token {
            "OI" => &mut flags.object_inherit,
            "CI" => &mut flags.container_inherit,
            "NP" => &mut flags.no_propagate,
            "IO" => &mut flags.inherit_only,
            "ID" => &mut flags.inherited,
            _ => return Err(SddlErrorKind::UnknownAceFlag),
        };
        if *slot {
            return Err(SddlErrorKind::DuplicateAceFlag);
        }
        *slot = true;
    }
    Ok(flags)
}

fn parse_rights(kind: AceType, text: &str) -> Result<u32, SddlErrorKind> {
    if text.is_empty() {
        return Err(SddlErrorKind::EmptyRights);
    }
    if let Some(digits) = text.strip_prefix("0x") {
        let canonical = (1..=8).contains(&digits.len())
            && digits
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && (digits == "0" || !digits.starts_with('0'));
        if !canonical {
            return Err(SddlErrorKind::InvalidHexRights);
        }
        return u32::from_str_radix(digits, 16).map_err(|_| SddlErrorKind::InvalidHexRights);
    }
    let table: &[(&str, u32)] = match kind {
        AceType::MandatoryLabel => &LABEL_ALIASES,
        AceType::Allow | AceType::Deny => &RIGHT_ALIASES,
    };
    let tokens = two_letter_tokens(text).ok_or(SddlErrorKind::UnknownRight)?;
    let mut seen: Vec<&str> = Vec::new();
    let mut mask = 0u32;
    for token in tokens {
        let bits = table
            .iter()
            .find(|(alias, _)| *alias == token)
            .map(|(_, bits)| *bits)
            .ok_or(SddlErrorKind::UnknownRight)?;
        if seen.contains(&token) {
            return Err(SddlErrorKind::DuplicateRight);
        }
        seen.push(token);
        mask |= bits;
    }
    Ok(mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
    const CONTAINER: &str =
        "S-1-15-2-2434737943-167758768-3180539153-984336765-1107280622-3591121930-2677285773";

    fn user() -> Sid {
        Sid::parse(USER).unwrap()
    }

    fn container() -> Sid {
        Sid::parse(CONTAINER).unwrap()
    }

    fn descriptor() -> SecurityDescriptor {
        SecurityDescriptor {
            owner: Some(user()),
            group: None,
            dacl: Some(Acl {
                flags: AclFlags {
                    protected: true,
                    ..AclFlags::default()
                },
                null: false,
                aces: vec![
                    Ace::allow(0x001f_01ff, user()),
                    Ace::allow(0x0010_0083, container()),
                ],
            }),
            sacl: Some(Acl {
                aces: vec![Ace::label(0x1, Sid::parse("LW").unwrap())],
                ..Acl::default()
            }),
        }
    }

    #[test]
    fn sids_read_in_string_form_and_by_alias() {
        let sid = user();
        assert_eq!(sid.authority(), 5);
        assert_eq!(
            sid.sub_authorities(),
            &[21, 1_004_336_348, 1_177_238_915, 682_003_330, 1001]
        );
        assert_eq!(sid.to_string(), USER);
        assert_eq!(sid.alias(), None);
        assert_eq!(sid.sddl_token(), USER);
        for (alias, text) in [
            ("SY", "S-1-5-18"),
            ("WD", "S-1-1-0"),
            ("BA", "S-1-5-32-544"),
            ("LW", "S-1-16-4096"),
            ("AC", "S-1-15-2-1"),
            ("OW", "S-1-3-4"),
        ] {
            let by_alias = Sid::parse(alias).unwrap();
            assert_eq!(by_alias, Sid::parse(text).unwrap(), "{alias}");
            assert_eq!(by_alias.to_string(), text);
            assert_eq!(by_alias.sddl_token(), alias);
        }
        assert_eq!(
            serde_json::to_string(&Sid::parse("SY").unwrap()).unwrap(),
            "\"S-1-5-18\""
        );
    }

    #[test]
    fn sids_outside_the_canonical_form_are_refused() {
        for (text, kind) in [
            ("S-2-5-18", SddlErrorKind::InvalidSid),
            ("S-1-05-18", SddlErrorKind::InvalidSid),
            ("S-1-5-018", SddlErrorKind::InvalidSid),
            ("S-1-5--18", SddlErrorKind::InvalidSid),
            ("S-1-5-18-", SddlErrorKind::InvalidSid),
            ("S-1-0x5-18", SddlErrorKind::UnexpectedToken),
            ("S-1-5-4294967296", SddlErrorKind::InvalidSid),
            ("S-1", SddlErrorKind::InvalidSid),
            ("S-1-5-+18", SddlErrorKind::InvalidSid),
            ("s-1-5-18", SddlErrorKind::InvalidSid),
            ("XX", SddlErrorKind::UnknownSidAlias),
            ("DA", SddlErrorKind::UnknownSidAlias),
            ("sy", SddlErrorKind::InvalidSid),
            ("SYS", SddlErrorKind::UnexpectedToken),
            (
                "S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15-16",
                SddlErrorKind::TooManySubAuthorities,
            ),
        ] {
            assert_eq!(
                Sid::parse(text).map_err(|error| error.kind),
                Err(kind),
                "{text}"
            );
        }
        assert!(Sid::parse("S-1-5").is_ok());
        assert!(Sid::parse("S-1-5-1-2-3-4-5-6-7-8-9-10-11-12-13-14-15").is_ok());
        assert_eq!(
            Sid::new(5, &[0; 16]).map_err(|error| error.kind),
            Err(SddlErrorKind::TooManySubAuthorities)
        );
    }

    #[test]
    fn the_writer_renders_as_windows_does_and_the_reader_reads_it_back() {
        let text = descriptor().to_sddl();
        assert_eq!(
            text,
            format!("O:{USER}D:P(A;;FA;;;{USER})(A;;0x100083;;;{CONTAINER})S:(ML;;NW;;;LW)")
        );
        assert_eq!(SecurityDescriptor::parse(&text), Ok(descriptor()));
    }

    #[test]
    fn rights_and_sids_compare_by_value_whatever_their_spelling() {
        let spelled = format!(
            "O:{USER}D:P(A;;0x1f01ff;;;{USER})(A;;0x100083;;;{CONTAINER})S:(ML;;0x1;;;S-1-16-4096)"
        );
        assert_eq!(SecurityDescriptor::parse(&spelled), Ok(descriptor()));
        let parsed = SecurityDescriptor::parse("D:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;SY)").unwrap();
        assert_eq!(parsed.dacl.unwrap().aces[0].mask, 0x000f_01ff);
        let parsed = SecurityDescriptor::parse("S:(ML;;NWNR;;;ME)").unwrap();
        assert_eq!(parsed.sacl.as_ref().unwrap().aces[0].mask, 0x3);
        assert_eq!(parsed.to_sddl(), "S:(ML;;NWNR;;;ME)");
    }

    #[test]
    fn a_full_read_back_with_group_flags_and_inheritance_parses() {
        let text = "O:BAG:SYD:PAI(A;OICIID;FA;;;SY)(D;;WDWO;;;WD)S:AI(ML;;NW;;;LW)";
        let parsed = SecurityDescriptor::parse(text).unwrap();
        assert_eq!(parsed.owner, Some(Sid::parse("S-1-5-32-544").unwrap()));
        assert_eq!(parsed.group, Some(Sid::parse("S-1-5-18").unwrap()));
        let dacl = parsed.dacl.as_ref().unwrap();
        assert!(dacl.flags.protected && dacl.flags.auto_inherited);
        assert!(dacl.aces[0].flags.inherited && dacl.aces[0].flags.object_inherit);
        assert_eq!(dacl.aces[1].kind, AceType::Deny);
        assert_eq!(dacl.aces[1].mask, 0x000c_0000);
        assert_eq!(
            parsed.to_sddl(),
            "O:BAG:SYD:PAI(A;OICIID;FA;;;SY)(D;;0xc0000;;;WD)S:AI(ML;;NW;;;LW)"
        );
        assert_eq!(SecurityDescriptor::parse(&parsed.to_sddl()), Ok(parsed));
        let null = SecurityDescriptor::parse("D:NO_ACCESS_CONTROL").unwrap();
        assert!(null.dacl.unwrap().null);
        assert_eq!(
            SecurityDescriptor::parse("D:").unwrap().dacl,
            Some(Acl::default())
        );
    }

    #[test]
    fn everything_outside_the_grammar_is_refused_where_it_starts() {
        let user_ace = format!("(A;;FA;;;{USER})");
        for (text, offset, kind) in [
            (String::new(), 0, SddlErrorKind::Empty),
            ("D:P ".to_owned(), 3, SddlErrorKind::InvalidCharacter),
            ("D:P\n".to_owned(), 3, SddlErrorKind::InvalidCharacter),
            (
                "D:P(A;;FA;;;SY)é".to_owned(),
                15,
                SddlErrorKind::InvalidCharacter,
            ),
            ("d:P".to_owned(), 0, SddlErrorKind::UnexpectedToken),
            ("X:SY".to_owned(), 0, SddlErrorKind::UnexpectedToken),
            ("O:SYO:SY".to_owned(), 4, SddlErrorKind::DuplicateSection),
            ("D:PO:SY".to_owned(), 3, SddlErrorKind::SectionOrder),
            ("O:SYjunk".to_owned(), 4, SddlErrorKind::UnexpectedToken),
            ("D:PP".to_owned(), 3, SddlErrorKind::DuplicateFlag),
            (
                "D:NO_ACCESS_CONTROLP".to_owned(),
                19,
                SddlErrorKind::UnexpectedToken,
            ),
            (
                "D:NO_ACCESS_CONTROL(A;;FA;;;SY)".to_owned(),
                19,
                SddlErrorKind::NullAclWithAces,
            ),
            ("D:Q".to_owned(), 2, SddlErrorKind::UnexpectedToken),
            (
                "D:(AU;;FA;;;SY)".to_owned(),
                3,
                SddlErrorKind::UnsupportedAceType,
            ),
            (
                "D:(OA;;FA;;;SY)".to_owned(),
                3,
                SddlErrorKind::UnsupportedAceType,
            ),
            (
                "D:(a;;FA;;;SY)".to_owned(),
                3,
                SddlErrorKind::UnsupportedAceType,
            ),
            (
                "D:(ML;;NW;;;LW)".to_owned(),
                3,
                SddlErrorKind::AceOutOfPlace,
            ),
            ("S:(A;;FA;;;SY)".to_owned(), 3, SddlErrorKind::AceOutOfPlace),
            (
                "D:(A;XX;FA;;;SY)".to_owned(),
                5,
                SddlErrorKind::UnknownAceFlag,
            ),
            (
                "D:(A;CIC;FA;;;SY)".to_owned(),
                5,
                SddlErrorKind::UnknownAceFlag,
            ),
            (
                "D:(A;CICI;FA;;;SY)".to_owned(),
                5,
                SddlErrorKind::DuplicateAceFlag,
            ),
            ("D:(A;;;;;SY)".to_owned(), 6, SddlErrorKind::EmptyRights),
            (
                "D:(A;;0X1F01FF;;;SY)".to_owned(),
                6,
                SddlErrorKind::UnknownRight,
            ),
            (
                "D:(A;;0x1F01FF;;;SY)".to_owned(),
                6,
                SddlErrorKind::InvalidHexRights,
            ),
            (
                "D:(A;;0x01f01ff;;;SY)".to_owned(),
                6,
                SddlErrorKind::InvalidHexRights,
            ),
            (
                "D:(A;;0x;;;SY)".to_owned(),
                6,
                SddlErrorKind::InvalidHexRights,
            ),
            (
                "D:(A;;0x100000000;;;SY)".to_owned(),
                6,
                SddlErrorKind::InvalidHexRights,
            ),
            ("D:(A;;fa;;;SY)".to_owned(), 6, SddlErrorKind::UnknownRight),
            ("D:(A;;NW;;;SY)".to_owned(), 6, SddlErrorKind::UnknownRight),
            ("S:(ML;;FA;;;LW)".to_owned(), 7, SddlErrorKind::UnknownRight),
            (
                "D:(A;;FAFA;;;SY)".to_owned(),
                6,
                SddlErrorKind::DuplicateRight,
            ),
            ("D:(A;;FAF;;;SY)".to_owned(), 6, SddlErrorKind::UnknownRight),
            (
                "D:(A;;FA;00000000-0000-0000-0000-000000000000;;SY)".to_owned(),
                9,
                SddlErrorKind::ObjectAce,
            ),
            ("D:(A;;FA;;x;SY)".to_owned(), 10, SddlErrorKind::ObjectAce),
            (
                "D:(A;;FA;;;SY;x)".to_owned(),
                13,
                SddlErrorKind::ExtraAceField,
            ),
            (
                "D:(A;;FA;;;SY".to_owned(),
                13,
                SddlErrorKind::UnterminatedAce,
            ),
            (
                "D:(A;;FA;;SY)".to_owned(),
                12,
                SddlErrorKind::UnterminatedAce,
            ),
            ("D:(A;;FA)".to_owned(), 8, SddlErrorKind::UnterminatedAce),
            (
                "D:(A;;FA;;;XX)".to_owned(),
                11,
                SddlErrorKind::UnknownSidAlias,
            ),
            (
                "D:(A;;FA;;;S-1-5-018)".to_owned(),
                11,
                SddlErrorKind::InvalidSid,
            ),
            (
                format!("D:{user_ace}x"),
                2 + user_ace.len(),
                SddlErrorKind::UnexpectedToken,
            ),
            (
                format!("D:{}", "(A;;FA;;;SY)".repeat(MAX_ACES + 1)),
                2 + 12 * MAX_ACES,
                SddlErrorKind::TooManyAces,
            ),
            (
                "O:".to_owned() + &"S".repeat(MAX_SDDL_BYTES),
                MAX_SDDL_BYTES,
                SddlErrorKind::TooLong,
            ),
        ] {
            assert_eq!(
                SecurityDescriptor::parse(&text),
                Err(SddlError { offset, kind }),
                "{text}"
            );
        }
    }

    #[test]
    fn errors_say_where_and_what() {
        let error = SecurityDescriptor::parse("D:(AU;;FA;;;SY)").unwrap_err();
        assert_eq!(
            error.to_string(),
            "SDDL at byte 3: an ACE type other than A, D and ML"
        );
        assert_eq!(
            serde_json::to_value(error).unwrap(),
            serde_json::json!({"offset": 3, "kind": "unsupported_ace_type"})
        );
    }
}
