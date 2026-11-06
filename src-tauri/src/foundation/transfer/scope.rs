//! The object and range scope of a transfer (S2 CORE-05 "object/range scope"; S3.7
//! explicit object budgets). Objects are named by the shared [`ContentKey`]; equal
//! content is not permission (S3.3), so a transfer moves an object only because its own
//! envelope's scope names it.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::range::{ByteRange, RangeSet};
use crate::foundation::ids::ContentKey;

/// Why a scope was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScopeError {
    /// An object holds at least one byte.
    ZeroSizeObject,
    /// An object in the scope grants at least one range.
    NoRanges,
    RangeBeyondObject {
        end_bytes: u64,
        size_bytes: u64,
    },
    /// A scope names at least one object.
    Empty,
    DuplicateObject {
        object: ContentKey,
    },
    /// Serialized objects are sorted by content key, so a scope has one encoding.
    NotCanonical,
    /// The granted bytes of all objects together do not fit in 64 bits.
    TooLarge,
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroSizeObject => f.write_str("an object in a transfer holds at least one byte"),
            Self::NoRanges => f.write_str("each object in a transfer grants at least one range"),
            Self::RangeBeyondObject {
                end_bytes,
                size_bytes,
            } => write!(
                f,
                "a granted range ends at {end_bytes}, past the object's {size_bytes} bytes"
            ),
            Self::Empty => f.write_str("a transfer names at least one object"),
            Self::DuplicateObject { object } => write!(f, "object {object} is named twice"),
            Self::NotCanonical => f.write_str("objects must be listed in content-key order"),
            Self::TooLarge => f.write_str("the granted bytes do not fit in 64 bits"),
        }
    }
}

impl std::error::Error for ScopeError {}

/// What a transfer may move of one object: the object's size and the granted ranges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ObjectGrant {
    size_bytes: u64,
    granted: RangeSet,
}

impl ObjectGrant {
    /// Every byte of an object of `size_bytes`.
    pub fn whole(size_bytes: u64) -> Result<Self, ScopeError> {
        let range = ByteRange::new(0, size_bytes).map_err(|_| ScopeError::ZeroSizeObject)?;
        Ok(Self {
            size_bytes,
            granted: RangeSet::single(range),
        })
    }

    /// The `granted` ranges of an object of `size_bytes`.
    pub fn ranges(size_bytes: u64, granted: RangeSet) -> Result<Self, ScopeError> {
        if size_bytes == 0 {
            return Err(ScopeError::ZeroSizeObject);
        }
        match granted.end_bytes() {
            None => Err(ScopeError::NoRanges),
            Some(end_bytes) if end_bytes > size_bytes => Err(ScopeError::RangeBeyondObject {
                end_bytes,
                size_bytes,
            }),
            Some(_) => Ok(Self {
                size_bytes,
                granted,
            }),
        }
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn granted(&self) -> &RangeSet {
        &self.granted
    }

    pub fn granted_bytes(&self) -> u64 {
        self.granted.total_bytes()
    }
}

/// The objects and byte ranges one transfer may move (S2 CORE-05, S3.7). Anything
/// outside it is refused, however the transfer is retried (INT-08).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "Vec<ScopeEntry>", into = "Vec<ScopeEntry>")]
pub struct TransferScope {
    objects: BTreeMap<ContentKey, ObjectGrant>,
    total_bytes: u64,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ScopeEntry {
    object: ContentKey,
    size_bytes: u64,
    ranges: RangeSet,
}

impl TryFrom<Vec<ScopeEntry>> for TransferScope {
    type Error = ScopeError;

    /// Only the canonical form is accepted: objects strictly in content-key order.
    fn try_from(entries: Vec<ScopeEntry>) -> Result<Self, Self::Error> {
        for pair in entries.windows(2) {
            if let [left, right] = pair {
                if left.object == right.object {
                    return Err(ScopeError::DuplicateObject {
                        object: left.object,
                    });
                }
                if left.object > right.object {
                    return Err(ScopeError::NotCanonical);
                }
            }
        }
        let objects = entries
            .into_iter()
            .map(|entry| {
                ObjectGrant::ranges(entry.size_bytes, entry.ranges)
                    .map(|grant| (entry.object, grant))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(objects)
    }
}

impl From<TransferScope> for Vec<ScopeEntry> {
    fn from(scope: TransferScope) -> Self {
        scope
            .objects
            .into_iter()
            .map(|(object, grant)| ScopeEntry {
                object,
                size_bytes: grant.size_bytes,
                ranges: grant.granted,
            })
            .collect()
    }
}

impl TransferScope {
    pub fn new(
        objects: impl IntoIterator<Item = (ContentKey, ObjectGrant)>,
    ) -> Result<Self, ScopeError> {
        let mut map = BTreeMap::new();
        let mut total_bytes = 0u64;
        for (object, grant) in objects {
            total_bytes = total_bytes
                .checked_add(grant.granted_bytes())
                .ok_or(ScopeError::TooLarge)?;
            if map.insert(object, grant).is_some() {
                return Err(ScopeError::DuplicateObject { object });
            }
        }
        if map.is_empty() {
            return Err(ScopeError::Empty);
        }
        Ok(Self {
            objects: map,
            total_bytes,
        })
    }

    pub fn single(object: ContentKey, grant: ObjectGrant) -> Self {
        let total_bytes = grant.granted_bytes();
        Self {
            objects: BTreeMap::from([(object, grant)]),
            total_bytes,
        }
    }

    pub fn objects(&self) -> &BTreeMap<ContentKey, ObjectGrant> {
        &self.objects
    }

    pub fn grant(&self, object: &ContentKey) -> Option<&ObjectGrant> {
        self.objects.get(object)
    }

    /// The granted bytes of every object together.
    pub fn total_bytes(&self) -> u64 {
        self.total_bytes
    }

    /// What `self` grants beyond `original`, per object; empty when `self` lies within
    /// it. An object recorded with another size counts entirely as beyond.
    pub fn beyond(&self, original: &TransferScope) -> BTreeMap<ContentKey, RangeSet> {
        self.objects
            .iter()
            .filter_map(|(object, grant)| {
                let extra = match original.objects.get(object) {
                    Some(before) if before.size_bytes == grant.size_bytes => {
                        grant.granted.difference(&before.granted)
                    }
                    _ => grant.granted.clone(),
                };
                (!extra.is_empty()).then_some((*object, extra))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    fn object(name: &str) -> ContentKey {
        ContentKey::from_digest(digest("yougori/test/object/v1", &[name.as_bytes()]))
    }

    fn set(pairs: &[(u64, u64)]) -> RangeSet {
        RangeSet::from_ranges(
            pairs
                .iter()
                .map(|&(start, end)| ByteRange::new(start, end).unwrap()),
        )
    }

    #[test]
    fn object_grants_stay_inside_the_object() {
        assert_eq!(ObjectGrant::whole(0), Err(ScopeError::ZeroSizeObject));
        assert_eq!(
            ObjectGrant::ranges(0, set(&[(0, 1)])),
            Err(ScopeError::ZeroSizeObject)
        );
        assert_eq!(
            ObjectGrant::ranges(10, RangeSet::new()),
            Err(ScopeError::NoRanges)
        );
        assert_eq!(
            ObjectGrant::ranges(10, set(&[(0, 4), (8, 11)])),
            Err(ScopeError::RangeBeyondObject {
                end_bytes: 11,
                size_bytes: 10
            })
        );
        let grant = ObjectGrant::ranges(10, set(&[(0, 4), (8, 10)])).unwrap();
        assert_eq!(grant.granted_bytes(), 6);
        assert_eq!(ObjectGrant::whole(10).unwrap().granted_bytes(), 10);
    }

    #[test]
    fn scopes_are_non_empty_and_name_each_object_once() {
        assert_eq!(TransferScope::new([]), Err(ScopeError::Empty));
        let duplicate = TransferScope::new([
            (object("a"), ObjectGrant::whole(1).unwrap()),
            (object("a"), ObjectGrant::whole(2).unwrap()),
        ]);
        assert_eq!(
            duplicate,
            Err(ScopeError::DuplicateObject {
                object: object("a")
            })
        );
        let huge = TransferScope::new([
            (object("a"), ObjectGrant::whole(u64::MAX).unwrap()),
            (object("b"), ObjectGrant::whole(1).unwrap()),
        ]);
        assert_eq!(huge, Err(ScopeError::TooLarge));
        let scope = TransferScope::new([
            (object("a"), ObjectGrant::whole(10).unwrap()),
            (
                object("b"),
                ObjectGrant::ranges(100, set(&[(0, 5)])).unwrap(),
            ),
        ])
        .unwrap();
        assert_eq!(scope.total_bytes(), 15);
        assert!(scope.grant(&object("c")).is_none());
    }

    #[test]
    fn beyond_lists_only_what_widens_the_original() {
        let original = TransferScope::new([
            (
                object("a"),
                ObjectGrant::ranges(100, set(&[(0, 50)])).unwrap(),
            ),
            (object("b"), ObjectGrant::whole(10).unwrap()),
        ])
        .unwrap();
        let narrower = TransferScope::single(
            object("a"),
            ObjectGrant::ranges(100, set(&[(10, 20)])).unwrap(),
        );
        assert!(narrower.beyond(&original).is_empty());
        let wider = TransferScope::new([
            (
                object("a"),
                ObjectGrant::ranges(100, set(&[(0, 60)])).unwrap(),
            ),
            (object("c"), ObjectGrant::whole(5).unwrap()),
        ])
        .unwrap();
        assert_eq!(
            wider.beyond(&original),
            BTreeMap::from([
                (object("a"), set(&[(50, 60)])),
                (object("c"), set(&[(0, 5)]))
            ])
        );
        let resized = TransferScope::single(object("b"), ObjectGrant::whole(11).unwrap());
        assert_eq!(
            resized.beyond(&original),
            BTreeMap::from([(object("b"), set(&[(0, 11)]))])
        );
    }

    #[test]
    fn serialized_scopes_must_be_canonical() {
        let scope = TransferScope::new([
            (object("a"), ObjectGrant::whole(10).unwrap()),
            (object("b"), ObjectGrant::whole(20).unwrap()),
        ])
        .unwrap();
        let json = serde_json::to_value(&scope).unwrap();
        assert_eq!(
            serde_json::from_value::<TransferScope>(json.clone()).unwrap(),
            scope
        );
        let mut reversed = json.clone();
        reversed.as_array_mut().unwrap().reverse();
        assert!(serde_json::from_value::<TransferScope>(reversed).is_err());
        let mut repeated = json.clone();
        let first = repeated[0].clone();
        repeated.as_array_mut().unwrap().insert(0, first);
        assert!(serde_json::from_value::<TransferScope>(repeated).is_err());
        let mut beyond = json.clone();
        beyond[0]["size_bytes"] = 5.into();
        assert!(serde_json::from_value::<TransferScope>(beyond).is_err());
        let mut unknown = json;
        unknown[0]["note"] = "x".into();
        assert!(serde_json::from_value::<TransferScope>(unknown).is_err());
        assert!(serde_json::from_str::<TransferScope>("[]").is_err());
    }
}
