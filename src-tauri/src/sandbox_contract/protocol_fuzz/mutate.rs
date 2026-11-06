//! The mutators of the fuzzer (VM-W50): bit flips, byte insertion and deletion,
//! boundary values written into length and count fields, splices of valid seeds, and
//! truncation. A [`Grammar`] holds what one target tells them about its input: the valid
//! seeds, a dictionary of tokens worth inserting, its documented limits, where its length
//! and count fields are, and the longest input worth trying.

use super::rng::SplitMix64;

/// How a length or count field is written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Encoding {
    /// Big-endian binary of this many bytes (1, 2, 4 or 8).
    BigEndian(usize),
    /// ASCII decimal digits.
    Decimal,
    /// ASCII hexadecimal digits.
    Hex,
}

/// One length or count field of an input: the bytes `start..end` and how they are written.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Field {
    pub(super) start: usize,
    pub(super) end: usize,
    pub(super) encoding: Encoding,
}

impl Field {
    /// A big-endian field of `width` bytes at `start`.
    pub(super) const fn binary(start: usize, width: usize) -> Self {
        Self {
            start,
            end: start + width,
            encoding: Encoding::BigEndian(width),
        }
    }
}

/// The mutation operators.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) enum Mutation {
    BitFlip,
    Insert,
    Delete,
    Boundary,
    Splice,
    Truncate,
}

/// Every operator, drawn with equal weight.
pub(super) const MUTATIONS: [Mutation; 6] = [
    Mutation::BitFlip,
    Mutation::Insert,
    Mutation::Delete,
    Mutation::Boundary,
    Mutation::Splice,
    Mutation::Truncate,
];

/// Small values and the edges of every integer width, written into fields beside a
/// target's own limits.
const EDGES: [u64; 22] = [
    0,
    1,
    2,
    7,
    8,
    0x7F,
    0x80,
    0xFF,
    0x100,
    0x3FF,
    0x7FFF,
    0x8000,
    0xFFFF,
    0x1_0000,
    0x7FFF_FFFF,
    0x8000_0000,
    0xFFFF_FFFF,
    0x1_0000_0000,
    0x7FFF_FFFF_FFFF_FFFF,
    0x8000_0000_0000_0000,
    u64::MAX - 1,
    u64::MAX,
];

/// What the mutators know about one target's input format.
pub(super) struct Grammar {
    /// Valid inputs, the starting points and splice partners.
    pub(super) seeds: Vec<Vec<u8>>,
    /// Tokens worth inserting, such as delimiters, keywords and field names.
    pub(super) dictionary: Vec<Vec<u8>>,
    /// The documented limits; each is tried with its neighbours.
    pub(super) limits: Vec<u64>,
    /// Finds the length and count fields of an input.
    pub(super) fields: fn(&[u8]) -> Vec<Field>,
    /// Inputs are cut to this length.
    pub(super) max_len: usize,
}

impl Grammar {
    /// A mutated input: a random seed with one to four stacked mutations, cut to
    /// `max_len`. `used` counts the operators applied.
    pub(super) fn generate(&self, rng: &mut SplitMix64, used: &mut [u64; 6]) -> Vec<u8> {
        let mut input = rng.pick(&self.seeds).clone();
        for _ in 0..rng.between(1, 4) {
            let mutation = self.mutate(rng, &mut input);
            if let Some(index) = MUTATIONS.iter().position(|known| *known == mutation) {
                used[index] += 1;
            }
        }
        input.truncate(self.max_len);
        input
    }

    /// Applies one random operator to `input` and returns it.
    pub(super) fn mutate(&self, rng: &mut SplitMix64, input: &mut Vec<u8>) -> Mutation {
        let mutation = *rng.pick(&MUTATIONS);
        match mutation {
            Mutation::BitFlip => flip(rng, input),
            Mutation::Insert => self.insert(rng, input),
            Mutation::Delete => delete(rng, input),
            Mutation::Boundary => self.boundary(rng, input),
            Mutation::Splice => self.splice(rng, input),
            Mutation::Truncate => truncate(rng, input),
        }
        mutation
    }

    /// Inserts random bytes, a dictionary token, a run of one byte (now and then as long
    /// as the length cap, so size limits are crossed) or a copy of a piece of the input
    /// itself at a random position.
    fn insert(&self, rng: &mut SplitMix64, input: &mut Vec<u8>) {
        let at = rng.below(input.len() + 1);
        let bytes: Vec<u8> = match rng.below(4) {
            0 if !self.dictionary.is_empty() => rng.pick(&self.dictionary).clone(),
            1 => {
                let byte = rng.byte();
                let longest = if rng.one_in(16) {
                    self.max_len.max(1)
                } else {
                    256
                };
                vec![byte; rng.between(1, longest)]
            }
            2 if !input.is_empty() => {
                let start = rng.below(input.len());
                let end = rng.between(start + 1, input.len().min(start + 64));
                input[start..end].to_vec()
            }
            _ => (0..rng.between(1, 8)).map(|_| rng.byte()).collect(),
        };
        input.splice(at..at, bytes);
    }

    /// Writes a boundary value into one of the input's length or count fields, or into
    /// a random byte, word or double word when it has none or by chance.
    fn boundary(&self, rng: &mut SplitMix64, input: &mut Vec<u8>) {
        let fields = (self.fields)(input);
        let field = if fields.is_empty() || rng.one_in(5) {
            let width = *rng.pick(&[1, 2, 4]);
            if input.len() < width {
                return flip(rng, input);
            }
            Field::binary(rng.below(input.len() - width + 1), width)
        } else {
            *rng.pick(&fields)
        };
        let value = self.boundary_value(rng);
        let written: Vec<u8> = match field.encoding {
            Encoding::BigEndian(width) => value.to_be_bytes()[8 - width..].to_vec(),
            Encoding::Decimal => {
                let digits = value.to_string();
                match rng.below(10) {
                    // Past u64::MAX, with a leading zero, or signed.
                    0 => format!("{digits}0"),
                    1 => format!("0{digits}"),
                    2 => format!("-{digits}"),
                    3 => format!("+{digits}"),
                    _ => digits,
                }
                .into_bytes()
            }
            Encoding::Hex => {
                let digits = if rng.one_in(2) {
                    format!("{value:x}")
                } else {
                    format!("{value:X}")
                };
                match rng.below(6) {
                    // One digit past the most a u64 needs, or a leading zero.
                    0 => format!("{digits}0"),
                    1 => format!("0{digits}"),
                    _ => digits,
                }
                .into_bytes()
            }
        };
        if field.end <= input.len() && field.start <= field.end {
            input.splice(field.start..field.end, written);
        }
    }

    /// A value from [`EDGES`], or one of the target's limits or a neighbour of it.
    fn boundary_value(&self, rng: &mut SplitMix64) -> u64 {
        if self.limits.is_empty() || rng.one_in(3) {
            return *rng.pick(&EDGES);
        }
        let limit = *rng.pick(&self.limits);
        match rng.below(3) {
            0 => limit.saturating_sub(1),
            1 => limit,
            _ => limit.saturating_add(1),
        }
    }

    /// Joins a prefix of the input to a suffix of a random seed, or inserts a piece of a
    /// random seed into the input.
    fn splice(&self, rng: &mut SplitMix64, input: &mut Vec<u8>) {
        let other = rng.pick(&self.seeds);
        if rng.one_in(2) {
            input.truncate(rng.below(input.len() + 1));
            input.extend_from_slice(&other[rng.below(other.len() + 1)..]);
        } else if !other.is_empty() {
            let start = rng.below(other.len());
            let end = rng.between(start + 1, other.len());
            let at = rng.below(input.len() + 1);
            input.splice(at..at, other[start..end].iter().copied());
        }
    }
}

/// Flips one to three random bits, or appends a random byte to an empty input.
fn flip(rng: &mut SplitMix64, input: &mut Vec<u8>) {
    if input.is_empty() {
        input.push(rng.byte());
        return;
    }
    for _ in 0..rng.between(1, 3) {
        let at = rng.below(input.len());
        input[at] ^= 1 << rng.below(8);
    }
}

/// Deletes a random range: a few bytes usually, up to half the input sometimes.
fn delete(rng: &mut SplitMix64, input: &mut Vec<u8>) {
    if input.is_empty() {
        return;
    }
    let most = if rng.one_in(4) {
        (input.len() / 2).max(1)
    } else {
        input.len().min(16)
    };
    let length = rng.between(1, most);
    let start = rng.below(input.len() - length + 1);
    input.drain(start..start + length);
}

/// Cuts the input at a random length.
fn truncate(rng: &mut SplitMix64, input: &mut Vec<u8>) {
    let length = rng.below(input.len());
    input.truncate(length);
}

/// Every maximal run of bytes matching `matches` in `input[from..to]`, as fields written
/// with `encoding`.
pub(super) fn runs(
    input: &[u8],
    from: usize,
    to: usize,
    matches: fn(&u8) -> bool,
    encoding: Encoding,
) -> Vec<Field> {
    let mut fields = Vec::new();
    let mut index = from;
    let to = to.min(input.len());
    while index < to {
        if matches(&input[index]) {
            let start = index;
            while index < to && matches(&input[index]) {
                index += 1;
            }
            fields.push(Field {
                start,
                end: index,
                encoding,
            });
        } else {
            index += 1;
        }
    }
    fields
}

/// Every run of ASCII digits in the input, as decimal fields.
pub(super) fn decimal_fields(input: &[u8]) -> Vec<Field> {
    runs(input, 0, input.len(), u8::is_ascii_digit, Encoding::Decimal)
}

/// The name of the enum variant a `Debug` text starts with.
pub(super) fn variant(debug: &str) -> String {
    debug
        .split(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .next()
        .unwrap_or_default()
        .to_owned()
}

/// The first position of `needle` in `haystack`.
pub(super) fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[test]
fn every_mutator_runs_and_stays_within_the_length_cap() {
    let grammar = Grammar {
        seeds: vec![b"length=12;count=3".to_vec(), vec![0, 1, 2, 3, 4, 5, 6, 7]],
        dictionary: vec![b";".to_vec()],
        limits: vec![12],
        fields: decimal_fields,
        max_len: 40,
    };
    let mut rng = SplitMix64::new(0x00E0_1F00);
    let mut used = [0; 6];
    for _ in 0..2_000 {
        assert!(grammar.generate(&mut rng, &mut used).len() <= 40);
    }
    assert!(used.iter().all(|count| *count > 0), "{used:?}");
    assert_eq!(variant("TooShort { bytes: 3 }"), "TooShort");
    assert_eq!(variant("Syntax(Version)"), "Syntax");
    assert_eq!(find(b"a\r\n\r\nb", b"\r\n\r\n"), Some(1));
}
