//! The restricting-SID pass of a Windows access check, evaluated over a DACL's bytes, for
//! the launch layout's read check (M02; docs/combined-gpu-memory-and-vm-sandbox-plan.md:
//! VM-W19 row, line 2618; §7.3 lines 2378–2386).
//!
//! The QEMU process runs under a restricted token whose restricting SIDs are `Users`,
//! `RESTRICTED` and the logon session's SID ([`WindowsHostRestrictions`]). Windows grants
//! such a token an access only when both the normal check and a second check against the
//! restricting SIDs alone grant it. [`restricted_access`] is that second check on one
//! object's DACL, done as the kernel does it:
//!
//! - the ACEs are walked in their order, against the whole set of restricting SIDs at
//!   once (not one SID at a time): an allow ACE for any of them grants the bits not yet
//!   decided, a deny ACE for any of them denies the bits not yet granted, and the walk
//!   stops once every wanted bit is decided. So a deny for `Users` before an allow for
//!   `RESTRICTED` refuses, as it does on the host;
//! - inheritance: the DACL read back from an object already holds its inherited ACEs
//!   (flag `INHERITED_ACE`), in the order Windows applies them, so nothing is read from
//!   parent directories; ACEs marked `INHERIT_ONLY_ACE` apply only to children and are
//!   skipped;
//! - an allow ACE grants only the specific rights in its mask; generic bits in it grant
//!   nothing here (the kernel does not map an ACE's generic bits at check time). A deny
//!   ACE's generic bits are mapped to the file rights they stand for and deny those, so
//!   an unusual DACL can only make the check stricter;
//! - a conditional (callback) allow ACE grants nothing, since its condition cannot be
//!   evaluated here, and a conditional deny ACE denies as if its condition held;
//! - any other ACE type before the decision is a refusal ([`AclError::UnsupportedAce`]),
//!   and a DACL whose sizes do not add up is [`AclError::Malformed`];
//! - no DACL at all (a NULL DACL) grants every access, as Windows does; an empty DACL
//!   grants none.
//!
//! [`WindowsHostRestrictions`]: crate::sandbox::qemu::WindowsHostRestrictions

use std::collections::BTreeSet;
use std::fmt;

use serde::Serialize;

use crate::sandbox::qemu::RestrictingSid;

/// `FILE_READ_DATA`, and `FILE_LIST_DIRECTORY` on a directory.
pub const READ_DATA: u32 = 0x0000_0001;
/// `FILE_WRITE_DATA`, and `FILE_ADD_FILE` on a directory.
pub const WRITE_DATA: u32 = 0x0000_0002;
/// `FILE_APPEND_DATA`, and `FILE_ADD_SUBDIRECTORY` on a directory.
pub const APPEND_DATA: u32 = 0x0000_0004;
/// `FILE_READ_EA`: read extended attributes.
pub const READ_EA: u32 = 0x0000_0008;
/// `FILE_WRITE_EA`: write extended attributes.
pub const WRITE_EA: u32 = 0x0000_0010;
/// `FILE_EXECUTE`, and `FILE_TRAVERSE` on a directory.
pub const EXECUTE: u32 = 0x0000_0020;
/// `FILE_DELETE_CHILD`: delete a directory's entries.
pub const DELETE_CHILD: u32 = 0x0000_0040;
/// `FILE_READ_ATTRIBUTES`.
pub const READ_ATTRIBUTES: u32 = 0x0000_0080;
/// `FILE_WRITE_ATTRIBUTES`.
pub const WRITE_ATTRIBUTES: u32 = 0x0000_0100;
/// `DELETE`.
pub const DELETE: u32 = 0x0001_0000;
/// `READ_CONTROL`: read the security descriptor.
pub const READ_CONTROL: u32 = 0x0002_0000;
/// `WRITE_DAC`: change the DACL.
pub const WRITE_DAC: u32 = 0x0004_0000;
/// `WRITE_OWNER`: change the owner.
pub const WRITE_OWNER: u32 = 0x0008_0000;
/// `SYNCHRONIZE`: wait on the handle.
pub const SYNCHRONIZE: u32 = 0x0010_0000;
/// winnt.h's `FILE_GENERIC_READ`.
pub const FILE_GENERIC_READ: u32 =
    READ_CONTROL | READ_DATA | READ_ATTRIBUTES | READ_EA | SYNCHRONIZE;
/// winnt.h's `FILE_GENERIC_WRITE`.
pub const FILE_GENERIC_WRITE: u32 =
    READ_CONTROL | WRITE_DATA | WRITE_ATTRIBUTES | WRITE_EA | APPEND_DATA | SYNCHRONIZE;
/// winnt.h's `FILE_GENERIC_EXECUTE`.
pub const FILE_GENERIC_EXECUTE: u32 = READ_CONTROL | READ_ATTRIBUTES | EXECUTE | SYNCHRONIZE;
/// winnt.h's `FILE_ALL_ACCESS`.
pub const FILE_ALL_ACCESS: u32 = 0x001F_01FF;
/// `GENERIC_READ`, which file objects map to [`FILE_GENERIC_READ`].
pub const GENERIC_READ: u32 = 0x8000_0000;
/// `GENERIC_WRITE`, which file objects map to [`FILE_GENERIC_WRITE`].
pub const GENERIC_WRITE: u32 = 0x4000_0000;
/// `GENERIC_EXECUTE`, which file objects map to [`FILE_GENERIC_EXECUTE`].
pub const GENERIC_EXECUTE: u32 = 0x2000_0000;
/// `GENERIC_ALL`, which file objects map to [`FILE_ALL_ACCESS`].
pub const GENERIC_ALL: u32 = 0x1000_0000;

/// winnt.h's access-allowed ACE type.
pub const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;
/// winnt.h's access-denied ACE type.
pub const ACCESS_DENIED_ACE_TYPE: u8 = 1;
/// winnt.h's conditional access-allowed ACE type.
pub const ACCESS_ALLOWED_CALLBACK_ACE_TYPE: u8 = 9;
/// winnt.h's conditional access-denied ACE type.
pub const ACCESS_DENIED_CALLBACK_ACE_TYPE: u8 = 10;
/// The ACE is inherited by files.
pub const OBJECT_INHERIT_ACE: u8 = 0x01;
/// The ACE is inherited by subdirectories.
pub const CONTAINER_INHERIT_ACE: u8 = 0x02;
/// The ACE applies only to children, not to its object.
pub const INHERIT_ONLY_ACE: u8 = 0x08;
/// The ACE was inherited from the parent.
pub const INHERITED_ACE: u8 = 0x10;

const ACL_HEADER_BYTES: usize = 8;
const ACE_HEADER_BYTES: usize = 4;
const MAX_SUB_AUTHORITIES: usize = 15;

/// The names of the specific file rights, for refusals.
const RIGHT_NAMES: [(u32, &str); 15] = [
    (READ_DATA, "READ_DATA"),
    (WRITE_DATA, "WRITE_DATA"),
    (APPEND_DATA, "APPEND_DATA"),
    (READ_EA, "READ_EA"),
    (WRITE_EA, "WRITE_EA"),
    (EXECUTE, "EXECUTE"),
    (DELETE_CHILD, "DELETE_CHILD"),
    (READ_ATTRIBUTES, "READ_ATTRIBUTES"),
    (WRITE_ATTRIBUTES, "WRITE_ATTRIBUTES"),
    (DELETE, "DELETE"),
    (READ_CONTROL, "READ_CONTROL"),
    (WRITE_DAC, "WRITE_DAC"),
    (WRITE_OWNER, "WRITE_OWNER"),
    (SYNCHRONIZE, "SYNCHRONIZE"),
    (GENERIC_ALL, "GENERIC_ALL"),
];

/// The names of the rights in `mask`.
pub fn right_names(mask: u32) -> Vec<&'static str> {
    RIGHT_NAMES
        .iter()
        .filter(|(bit, _)| mask & bit != 0)
        .map(|(_, name)| *name)
        .collect()
}

/// What the restricted QEMU must be able to do with a path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathAccess {
    /// `FILE_GENERIC_READ`: read a file, or list a directory.
    Read,
    /// `FILE_GENERIC_READ | FILE_GENERIC_EXECUTE`: also execute a file, or traverse a
    /// directory, as loading the executable and its DLLs needs.
    ReadExecute,
}

impl PathAccess {
    /// The access mask the check wants.
    pub const fn mask(self) -> u32 {
        match self {
            Self::Read => FILE_GENERIC_READ,
            Self::ReadExecute => FILE_GENERIC_READ | FILE_GENERIC_EXECUTE,
        }
    }
}

impl fmt::Display for PathAccess {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::ReadExecute => "read and execute",
        })
    }
}

/// A SID in its binary form: revision 1, the sub-authority count, the six-byte
/// identifier authority (big-endian) and the sub-authorities (little-endian).
fn sid_bytes(authority: u8, sub_authorities: &[u32]) -> Vec<u8> {
    let mut bytes = vec![1, 0, 0, 0, 0, 0, 0, authority];
    bytes[1] = u8::try_from(sub_authorities.len()).unwrap_or(u8::MAX);
    for sub_authority in sub_authorities {
        bytes.extend_from_slice(&sub_authority.to_le_bytes());
    }
    bytes
}

/// `NT AUTHORITY\RESTRICTED`, S-1-5-12.
pub fn restricted_sid() -> Vec<u8> {
    sid_bytes(5, &[12])
}

/// `BUILTIN\Users`, S-1-5-32-545.
pub fn users_sid() -> Vec<u8> {
    sid_bytes(5, &[32, 545])
}

/// Why a logon SID was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LogonSidError {
    pub text: String,
}

impl fmt::Display for LogonSidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not a logon session SID (S-1-5-5-X-Y)",
            self.text
        )
    }
}

impl std::error::Error for LogonSidError {}

/// A logon session's SID, `S-1-5-5-X-Y`: the restricting SID the launcher grants on the
/// VM's own files.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct LogonSid {
    text: String,
    #[serde(skip_serializing)]
    bytes: Vec<u8>,
}

impl LogonSid {
    /// Reads `S-1-5-5-X-Y` with X and Y decimal 32-bit values.
    pub fn parse(text: &str) -> Result<Self, LogonSidError> {
        let error = || LogonSidError {
            text: text.to_owned(),
        };
        let rest = text.strip_prefix("S-1-5-5-").ok_or_else(error)?;
        let mut parts = rest.split('-');
        let mut next = || -> Result<u32, LogonSidError> {
            let part = parts.next().ok_or_else(error)?;
            if part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(error());
            }
            part.parse().map_err(|_| error())
        };
        let high = next()?;
        let low = next()?;
        if parts.next().is_some() {
            return Err(error());
        }
        Ok(Self {
            text: text.to_owned(),
            bytes: sid_bytes(5, &[5, high, low]),
        })
    }

    /// The SID's text, `S-1-5-5-X-Y`.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The SID's binary form.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl fmt::Display for LogonSid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// The restricting SIDs the second access check runs against: `RESTRICTED`, `Users` and,
/// when given, the logon session's SID.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Trustees {
    sids: Vec<(RestrictingSid, Vec<u8>)>,
}

impl Trustees {
    /// `RESTRICTED`, `Users` and, when given, `logon`.
    pub fn new(logon: Option<&LogonSid>) -> Self {
        let mut sids = vec![
            (RestrictingSid::Restricted, restricted_sid()),
            (RestrictingSid::Users, users_sid()),
        ];
        if let Some(logon) = logon {
            sids.push((RestrictingSid::LogonSession, logon.as_bytes().to_vec()));
        }
        Self { sids }
    }

    fn find(&self, sid: &[u8]) -> Option<RestrictingSid> {
        self.sids
            .iter()
            .find(|(_, bytes)| bytes.as_slice() == sid)
            .map(|(name, _)| *name)
    }
}

/// Why a DACL could not be evaluated.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum AclError {
    Malformed {
        detail: String,
    },
    /// An ACE of a type this check does not evaluate came before the decision.
    UnsupportedAce {
        ace_type: u8,
    },
}

impl fmt::Display for AclError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { detail } => write!(f, "the DACL is malformed: {detail}"),
            Self::UnsupportedAce { ace_type } => write!(
                f,
                "the DACL has an ACE of type {ace_type}, which this check does not evaluate, \
                 before the decision"
            ),
        }
    }
}

impl std::error::Error for AclError {}

/// The outcome of the restricting-SID pass for one wanted access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AccessOutcome {
    /// The wanted rights.
    pub wanted: u32,
    /// The wanted rights an allow ACE granted before any deny.
    pub granted: u32,
    /// The wanted rights a deny ACE denied before any grant.
    pub denied: u32,
    /// The restricting SIDs whose allow ACEs granted rights.
    pub through: BTreeSet<RestrictingSid>,
    /// The object has no DACL, which grants everything.
    pub null_dacl: bool,
}

impl AccessOutcome {
    /// Whether every wanted right is granted.
    pub fn allowed(&self) -> bool {
        self.granted & self.wanted == self.wanted
    }

    /// The wanted rights not granted.
    pub fn missing(&self) -> u32 {
        self.wanted & !self.granted
    }
}

/// The file rights a deny ACE's generic bits stand for.
fn map_generic(mask: u32) -> u32 {
    let mut mapped = mask & !(GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL);
    for (generic, specific) in [
        (GENERIC_READ, FILE_GENERIC_READ),
        (GENERIC_WRITE, FILE_GENERIC_WRITE),
        (GENERIC_EXECUTE, FILE_GENERIC_EXECUTE),
        (GENERIC_ALL, FILE_ALL_ACCESS),
    ] {
        if mask & generic != 0 {
            mapped |= specific;
        }
    }
    mapped
}

fn malformed(detail: &str) -> AclError {
    AclError::Malformed {
        detail: detail.to_owned(),
    }
}

fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair = bytes.get(offset..offset + 2)?;
    Some(u16::from_le_bytes([pair[0], pair[1]]))
}

fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    let quad = bytes.get(offset..offset + 4)?;
    Some(u32::from_le_bytes([quad[0], quad[1], quad[2], quad[3]]))
}

/// The SID at the start of `bytes`, exactly its length.
fn sid_at(bytes: &[u8]) -> Result<&[u8], AclError> {
    let count = usize::from(*bytes.get(1).ok_or_else(|| malformed("an ACE has no SID"))?);
    if bytes.first() != Some(&1) || count > MAX_SUB_AUTHORITIES {
        return Err(malformed("an ACE's SID has an unknown revision or size"));
    }
    bytes
        .get(..8 + 4 * count)
        .ok_or_else(|| malformed("an ACE's SID runs past the ACE"))
}

/// The restricting-SID pass for `wanted` on the DACL `acl` (`None` for a NULL DACL), as
/// the module notes describe.
pub fn restricted_access(
    acl: Option<&[u8]>,
    trustees: &Trustees,
    wanted: u32,
) -> Result<AccessOutcome, AclError> {
    let mut outcome = AccessOutcome {
        wanted,
        granted: 0,
        denied: 0,
        through: BTreeSet::new(),
        null_dacl: false,
    };
    let Some(acl) = acl else {
        outcome.granted = wanted;
        outcome.null_dacl = true;
        return Ok(outcome);
    };
    let revision = *acl
        .first()
        .ok_or_else(|| malformed("the ACL has no header"))?;
    if revision != 2 && revision != 4 {
        return Err(malformed("the ACL revision is not 2 or 4"));
    }
    let size = usize::from(u16_at(acl, 2).ok_or_else(|| malformed("the ACL has no header"))?);
    let count = u16_at(acl, 4).ok_or_else(|| malformed("the ACL has no header"))?;
    if size < ACL_HEADER_BYTES || size > acl.len() {
        return Err(malformed("the ACL size does not fit its bytes"));
    }
    let acl = &acl[..size];
    let mut offset = ACL_HEADER_BYTES;
    for _ in 0..count {
        let ace_type = *acl
            .get(offset)
            .ok_or_else(|| malformed("an ACE header runs past the ACL"))?;
        let flags = *acl
            .get(offset + 1)
            .ok_or_else(|| malformed("an ACE header runs past the ACL"))?;
        let ace_size = usize::from(
            u16_at(acl, offset + 2).ok_or_else(|| malformed("an ACE header runs past the ACL"))?,
        );
        if ace_size < ACE_HEADER_BYTES {
            return Err(malformed("an ACE is shorter than its header"));
        }
        let ace = acl
            .get(offset..offset + ace_size)
            .ok_or_else(|| malformed("an ACE runs past the ACL"))?;
        offset += ace_size;
        if (outcome.granted | outcome.denied) & wanted == wanted {
            break;
        }
        if flags & INHERIT_ONLY_ACE != 0 {
            continue;
        }
        match ace_type {
            ACCESS_ALLOWED_ACE_TYPE
            | ACCESS_DENIED_ACE_TYPE
            | ACCESS_ALLOWED_CALLBACK_ACE_TYPE
            | ACCESS_DENIED_CALLBACK_ACE_TYPE => {
                let mask = u32_at(ace, ACE_HEADER_BYTES)
                    .ok_or_else(|| malformed("an ACE has no access mask"))?;
                let sid = sid_at(&ace[ACE_HEADER_BYTES + 4..])?;
                let Some(trustee) = trustees.find(sid) else {
                    continue;
                };
                let open = wanted & !(outcome.granted | outcome.denied);
                match ace_type {
                    ACCESS_ALLOWED_ACE_TYPE => {
                        let granted = mask & open;
                        if granted != 0 {
                            outcome.granted |= granted;
                            outcome.through.insert(trustee);
                        }
                    }
                    ACCESS_ALLOWED_CALLBACK_ACE_TYPE => {}
                    _ => outcome.denied |= map_generic(mask) & open,
                }
            }
            other => return Err(AclError::UnsupportedAce { ace_type: other }),
        }
    }
    Ok(outcome)
}

/// Builds DACL bytes for the tests: `(type, flags, mask, sid)` per ACE.
#[cfg(test)]
pub fn acl_bytes(aces: &[(u8, u8, u32, &[u8])]) -> Vec<u8> {
    let mut body = Vec::new();
    for (ace_type, flags, mask, sid) in aces {
        let size = u16::try_from(ACE_HEADER_BYTES + 4 + sid.len()).unwrap();
        body.push(*ace_type);
        body.push(*flags);
        body.extend_from_slice(&size.to_le_bytes());
        body.extend_from_slice(&mask.to_le_bytes());
        body.extend_from_slice(sid);
    }
    let size = u16::try_from(ACL_HEADER_BYTES + body.len()).unwrap();
    let count = u16::try_from(aces.len()).unwrap();
    let mut acl = vec![2, 0];
    acl.extend_from_slice(&size.to_le_bytes());
    acl.extend_from_slice(&count.to_le_bytes());
    acl.extend_from_slice(&[0, 0]);
    acl.extend_from_slice(&body);
    acl
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALLOW: u8 = ACCESS_ALLOWED_ACE_TYPE;
    const DENY: u8 = ACCESS_DENIED_ACE_TYPE;
    const READ: u32 = FILE_GENERIC_READ;
    const READ_EXECUTE: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;

    fn everyone() -> Vec<u8> {
        sid_bytes(1, &[0])
    }

    fn authenticated_users() -> Vec<u8> {
        sid_bytes(5, &[11])
    }

    fn logon() -> LogonSid {
        LogonSid::parse("S-1-5-5-0-49647746").unwrap()
    }

    fn check(aces: &[(u8, u8, u32, &[u8])], wanted: u32) -> AccessOutcome {
        restricted_access(
            Some(&acl_bytes(aces)),
            &Trustees::new(Some(&logon())),
            wanted,
        )
        .unwrap()
    }

    #[test]
    fn well_known_sids_have_their_binary_form() {
        assert_eq!(restricted_sid(), [1, 1, 0, 0, 0, 0, 0, 5, 12, 0, 0, 0]);
        assert_eq!(
            users_sid(),
            [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x21, 0x02, 0, 0]
        );
        assert_eq!(
            logon().as_bytes(),
            [1, 3, 0, 0, 0, 0, 0, 5, 5, 0, 0, 0, 0, 0, 0, 0, 0x82, 0x90, 0xf5, 0x02]
        );
        assert_eq!(logon().as_str(), "S-1-5-5-0-49647746");
        for bad in [
            "S-1-5-32-545",
            "S-1-5-5-0",
            "S-1-5-5-0-1-2",
            "S-1-5-5--1",
            "S-1-5-5-0-+1",
            "S-1-5-5-0-4294967296",
            "s-1-5-5-0-1",
        ] {
            assert!(LogonSid::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn any_restricting_sid_may_grant() {
        let restricted = restricted_sid();
        let users = users_sid();
        let logon = logon();
        for (sid, name) in [
            (restricted.as_slice(), RestrictingSid::Restricted),
            (users.as_slice(), RestrictingSid::Users),
            (logon.as_bytes(), RestrictingSid::LogonSession),
        ] {
            let outcome = check(&[(ALLOW, 0, READ_EXECUTE, sid)], READ_EXECUTE);
            assert!(outcome.allowed(), "{name:?}");
            assert_eq!(outcome.through, BTreeSet::from([name]));
        }
        // Rights may come from several restricting SIDs together.
        let outcome = check(
            &[
                (ALLOW, 0, READ, &restricted),
                (ALLOW, 0, FILE_GENERIC_EXECUTE, &users),
            ],
            READ_EXECUTE,
        );
        assert!(outcome.allowed());
        assert_eq!(
            outcome.through,
            BTreeSet::from([RestrictingSid::Restricted, RestrictingSid::Users])
        );
    }

    #[test]
    fn other_sids_do_not_count_and_a_logon_sid_counts_only_when_given() {
        let everyone = everyone();
        let authenticated = authenticated_users();
        let outcome = check(
            &[
                (ALLOW, 0, FILE_ALL_ACCESS, &everyone),
                (ALLOW, 0, FILE_ALL_ACCESS, &authenticated),
            ],
            READ,
        );
        assert!(!outcome.allowed());
        assert_eq!(outcome.missing(), READ);
        let logon = logon();
        let acl = acl_bytes(&[(ALLOW, 0, READ, logon.as_bytes())]);
        let without = restricted_access(Some(&acl), &Trustees::new(None), READ).unwrap();
        assert!(!without.allowed());
    }

    #[test]
    fn a_deny_before_an_allow_refuses_and_after_it_does_not() {
        let users = users_sid();
        let restricted = restricted_sid();
        let denied_first = check(
            &[(DENY, 0, READ_DATA, &users), (ALLOW, 0, READ, &restricted)],
            READ,
        );
        assert!(!denied_first.allowed());
        assert_eq!(denied_first.missing(), READ_DATA);
        assert_eq!(denied_first.denied, READ_DATA);
        let allowed_first = check(
            &[(ALLOW, 0, READ, &restricted), (DENY, 0, READ_DATA, &users)],
            READ,
        );
        assert!(allowed_first.allowed());
        assert_eq!(allowed_first.denied, 0);
    }

    #[test]
    fn read_without_execute_is_not_read_and_execute() {
        let restricted = restricted_sid();
        let outcome = check(&[(ALLOW, 0, READ, &restricted)], READ_EXECUTE);
        assert!(!outcome.allowed());
        assert_eq!(right_names(outcome.missing()), vec!["EXECUTE"]);
    }

    #[test]
    fn inherit_only_aces_are_skipped_and_inherited_aces_count() {
        let restricted = restricted_sid();
        let inherit_only = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE | INHERIT_ONLY_ACE;
        let skipped = check(&[(ALLOW, inherit_only, READ, &restricted)], READ);
        assert!(!skipped.allowed());
        let denied_for_children = check(
            &[
                (DENY, inherit_only, READ, &restricted),
                (ALLOW, 0, READ, &restricted),
            ],
            READ,
        );
        assert!(denied_for_children.allowed());
        let inherited = check(&[(ALLOW, INHERITED_ACE, READ, &restricted)], READ);
        assert!(inherited.allowed());
    }

    #[test]
    fn generic_bits_never_grant_but_always_deny() {
        let restricted = restricted_sid();
        let generic_allow = check(&[(ALLOW, 0, GENERIC_READ, &restricted)], READ);
        assert!(!generic_allow.allowed());
        let generic_deny = check(
            &[
                (DENY, 0, GENERIC_ALL, &restricted),
                (ALLOW, 0, READ, &restricted),
            ],
            READ,
        );
        assert_eq!(generic_deny.denied, READ);
        assert!(!generic_deny.allowed());
    }

    #[test]
    fn conditional_aces_never_grant_but_deny() {
        let restricted = restricted_sid();
        let allow = check(
            &[(ACCESS_ALLOWED_CALLBACK_ACE_TYPE, 0, READ, &restricted)],
            READ,
        );
        assert!(!allow.allowed());
        let deny = check(
            &[
                (ACCESS_DENIED_CALLBACK_ACE_TYPE, 0, READ_DATA, &restricted),
                (ALLOW, 0, READ, &restricted),
            ],
            READ,
        );
        assert!(!deny.allowed());
    }

    #[test]
    fn unknown_ace_types_refuse_only_before_the_decision() {
        let restricted = restricted_sid();
        let acl = acl_bytes(&[(5, 0, READ, &restricted), (ALLOW, 0, READ, &restricted)]);
        assert_eq!(
            restricted_access(Some(&acl), &Trustees::new(None), READ),
            Err(AclError::UnsupportedAce { ace_type: 5 })
        );
        let acl = acl_bytes(&[(ALLOW, 0, READ, &restricted), (5, 0, READ, &restricted)]);
        assert!(restricted_access(Some(&acl), &Trustees::new(None), READ)
            .unwrap()
            .allowed());
    }

    #[test]
    fn null_and_empty_dacls() {
        let null = restricted_access(None, &Trustees::new(None), READ_EXECUTE).unwrap();
        assert!(null.allowed() && null.null_dacl);
        let empty = check(&[], READ);
        assert!(!empty.allowed());
        assert_eq!(empty.missing(), READ);
    }

    #[test]
    fn malformed_dacls_are_refused() {
        let restricted = restricted_sid();
        let good = acl_bytes(&[(ALLOW, 0, READ, &restricted)]);
        let trustees = Trustees::new(None);
        let mut revision = good.clone();
        revision[0] = 3;
        let mut size = good.clone();
        size[2] = u8::try_from(good.len() + 4).unwrap();
        let mut count = good.clone();
        count[4] = 2;
        let mut ace_size = good.clone();
        ace_size[10] = 2;
        let mut sid_count = good.clone();
        sid_count[ACL_HEADER_BYTES + 8 + 1] = 9;
        for (name, bytes) in [
            ("revision", revision),
            ("size", size),
            ("count", count),
            ("ace size", ace_size),
            ("sid count", sid_count),
            ("truncated", good[..5].to_vec()),
        ] {
            assert!(
                matches!(
                    restricted_access(Some(&bytes), &trustees, READ),
                    Err(AclError::Malformed { .. })
                ),
                "{name}"
            );
        }
    }

    /// The ACE type values are in a windows-sys feature the crate does not enable
    /// (`Win32_System_SystemServices`); they are winnt.h's 0, 1, 9 and 10.
    #[cfg(windows)]
    #[test]
    fn constants_are_the_windows_values() {
        use windows_sys::Win32::Foundation::{GENERIC_ALL as ALL, GENERIC_READ as GR};
        use windows_sys::Win32::Security::{
            CONTAINER_INHERIT_ACE as CI, INHERITED_ACE as INH, INHERIT_ONLY_ACE as IO,
            OBJECT_INHERIT_ACE as OI,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_ALL_ACCESS as FA, FILE_EXECUTE as FE, FILE_GENERIC_EXECUTE as GE,
            FILE_GENERIC_READ as GRD, FILE_GENERIC_WRITE as GW, FILE_READ_DATA as RD,
        };
        assert_eq!(FILE_GENERIC_READ, GRD);
        assert_eq!(FILE_GENERIC_WRITE, GW);
        assert_eq!(FILE_GENERIC_EXECUTE, GE);
        assert_eq!(FILE_ALL_ACCESS, FA);
        assert_eq!(READ_DATA, RD);
        assert_eq!(EXECUTE, FE);
        assert_eq!(GENERIC_READ, GR);
        assert_eq!(GENERIC_ALL, ALL);
        assert_eq!(u32::from(OBJECT_INHERIT_ACE), OI);
        assert_eq!(u32::from(CONTAINER_INHERIT_ACE), CI);
        assert_eq!(u32::from(INHERIT_ONLY_ACE), IO);
        assert_eq!(u32::from(INHERITED_ACE), INH);
    }
}
