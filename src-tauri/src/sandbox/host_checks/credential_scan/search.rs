//! A streaming search for every form of one fixture credential (§17 VM-CP-12, line
//! 3162).
//!
//! [`Search`] holds one Knuth-Morris-Pratt automaton per form; a [`Matcher`] runs them
//! over one file's bytes chunk by chunk, so a form split across two reads is still found
//! and the memory used is the forms' size, whatever the file's. Each byte costs at most
//! a constant amortized number of steps per form, so a hostile file cannot make the
//! search slower than linear in what was read. A matcher keeps, per encoding, the first
//! match (the one that ends first) and its offset; an encoding found in an earlier chunk
//! is not searched again in the same file.

use super::fixture::{Encoding, FixtureCredential};

/// One searched form and its failure table.
#[derive(Clone, Debug)]
struct Form {
    encoding: Encoding,
    bytes: Vec<u8>,
    /// `fail[i]`: the length of the longest proper prefix of `bytes[..=i]` that is also
    /// its suffix.
    fail: Vec<usize>,
}

impl Form {
    fn new(encoding: Encoding, bytes: Vec<u8>) -> Self {
        let mut fail = vec![0; bytes.len()];
        let mut length = 0;
        for index in 1..bytes.len() {
            while length > 0 && bytes[index] != bytes[length] {
                length = fail[length - 1];
            }
            if bytes[index] == bytes[length] {
                length += 1;
            }
            fail[index] = length;
        }
        Self {
            encoding,
            bytes,
            fail,
        }
    }

    /// The automaton's next state after `byte`; `bytes.len()` is a match.
    fn step(&self, mut state: usize, byte: u8) -> usize {
        if state == self.bytes.len() {
            state = self.fail[state - 1];
        }
        while state > 0 && self.bytes[state] != byte {
            state = self.fail[state - 1];
        }
        if self.bytes[state] == byte {
            state + 1
        } else {
            0
        }
    }
}

/// The search for every form of one fixture credential.
#[derive(Clone, Debug)]
pub struct Search {
    forms: Vec<Form>,
}

impl Search {
    pub fn new(fixture: &FixtureCredential) -> Self {
        Self {
            forms: fixture
                .forms()
                .into_iter()
                .filter(|(_, bytes)| !bytes.is_empty())
                .map(|(encoding, bytes)| Form::new(encoding, bytes))
                .collect(),
        }
    }

    /// A matcher for one file, at offset 0.
    pub fn matcher(&self) -> Matcher<'_> {
        Matcher {
            search: self,
            states: vec![0; self.forms.len()],
            offset: 0,
            first: [None; Encoding::ALL.len()],
        }
    }
}

/// Where a match lies in a file: its first byte's offset and the offset just past its
/// last byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Span {
    start: u64,
    end: u64,
}

/// The search over one file's bytes, fed in order.
#[derive(Clone, Debug)]
pub struct Matcher<'a> {
    search: &'a Search,
    states: Vec<usize>,
    /// How many bytes were fed.
    offset: u64,
    /// The first match of each encoding, by [`Encoding::index`].
    first: [Option<Span>; Encoding::ALL.len()],
}

impl Matcher<'_> {
    /// Searches the next `chunk` of the file.
    pub fn feed(&mut self, chunk: &[u8]) {
        let chunk_start = self.offset;
        for (form, state) in self.search.forms.iter().zip(self.states.iter_mut()) {
            let found = &mut self.first[form.encoding.index()];
            if found.is_some_and(|span| span.end <= chunk_start) {
                continue;
            }
            let length = form.bytes.len() as u64;
            for (index, byte) in chunk.iter().enumerate() {
                let end = chunk_start + index as u64 + 1;
                if found.is_some_and(|span| span.end <= end) {
                    break;
                }
                *state = form.step(*state, *byte);
                if *state == form.bytes.len() {
                    *found = Some(Span {
                        start: end - length,
                        end,
                    });
                    break;
                }
            }
        }
        self.offset += chunk.len() as u64;
    }

    /// How many bytes were fed.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// Each encoding found, with the offset of its first match, in [`Encoding::ALL`]
    /// order.
    pub fn found(&self) -> Vec<(Encoding, u64)> {
        Encoding::ALL
            .iter()
            .filter_map(|encoding| self.first[encoding.index()].map(|span| (*encoding, span.start)))
            .collect()
    }
}
