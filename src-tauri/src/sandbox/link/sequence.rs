//! Monotonically checked sequence state, one per direction of one connection (§3.2 line
//! 2067 "generation/connection binding and monotonically checked sequence state"; VM-R59
//! line 2924 "replay"). Sequences start at 1 on every connection and rise by exactly one
//! per frame; a repeated or lower sequence is a replay and a higher one a reorder or a
//! gap, and both are refused. A frame of an earlier connection is refused by its
//! connection field before its sequence is looked at.

use std::fmt;

use serde::Serialize;

/// Why a sequence was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "sequence_refusal", rename_all = "snake_case")]
pub enum SequenceRefusal {
    /// At or below the last accepted sequence.
    Replayed { sequence: u64, last_accepted: u64 },
    /// Above the next expected sequence: reordered, or frames were lost.
    Reordered { sequence: u64, expected: u64 },
    /// The direction has used every sequence; the link must be replaced.
    Exhausted,
}

impl SequenceRefusal {
    pub const fn code(self) -> &'static str {
        match self {
            Self::Replayed { .. } => "sequence.replayed",
            Self::Reordered { .. } => "sequence.reordered",
            Self::Exhausted => "sequence.exhausted",
        }
    }
}

impl fmt::Display for SequenceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Replayed {
                sequence,
                last_accepted,
            } => write!(
                f,
                "sequence {sequence} was already passed; the last accepted is {last_accepted}"
            ),
            Self::Reordered { sequence, expected } => {
                write!(
                    f,
                    "sequence {sequence} arrived where {expected} was expected"
                )
            }
            Self::Exhausted => f.write_str("the sequence space of this direction is used up"),
        }
    }
}

impl std::error::Error for SequenceRefusal {}

/// The sequence state of one direction.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct SequenceState {
    last_accepted: u64,
}

impl SequenceState {
    pub const fn new() -> Self {
        Self { last_accepted: 0 }
    }

    /// A state that has accepted or sent every sequence up to `last_accepted`.
    #[cfg(test)]
    pub(crate) const fn after(last_accepted: u64) -> Self {
        Self { last_accepted }
    }

    pub const fn last_accepted(self) -> u64 {
        self.last_accepted
    }

    /// The only sequence the next frame may carry, or `None` when exhausted.
    pub fn expected(self) -> Option<u64> {
        self.last_accepted.checked_add(1)
    }

    /// Accepts `sequence` only when it is exactly the expected one.
    pub fn accept(&mut self, sequence: u64) -> Result<(), SequenceRefusal> {
        let expected = self.expected().ok_or(SequenceRefusal::Exhausted)?;
        if sequence <= self.last_accepted {
            return Err(SequenceRefusal::Replayed {
                sequence,
                last_accepted: self.last_accepted,
            });
        }
        if sequence != expected {
            return Err(SequenceRefusal::Reordered { sequence, expected });
        }
        self.last_accepted = sequence;
        Ok(())
    }

    /// Takes the next sequence for a frame this side sends.
    pub fn next_for_send(&mut self) -> Result<u64, SequenceRefusal> {
        let next = self.expected().ok_or(SequenceRefusal::Exhausted)?;
        self.last_accepted = next;
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_next_sequence_is_accepted() {
        let mut state = SequenceState::new();
        assert_eq!(state.expected(), Some(1));
        assert_eq!(state.accept(1), Ok(()));
        assert_eq!(state.accept(2), Ok(()));
        assert_eq!(
            state.accept(2),
            Err(SequenceRefusal::Replayed {
                sequence: 2,
                last_accepted: 2
            })
        );
        assert_eq!(
            state.accept(1),
            Err(SequenceRefusal::Replayed {
                sequence: 1,
                last_accepted: 2
            })
        );
        assert_eq!(
            state.accept(0),
            Err(SequenceRefusal::Replayed {
                sequence: 0,
                last_accepted: 2
            })
        );
        assert_eq!(
            state.accept(4),
            Err(SequenceRefusal::Reordered {
                sequence: 4,
                expected: 3
            })
        );
        assert_eq!(state.accept(3), Ok(()));
        assert_eq!(state.last_accepted(), 3);
    }

    #[test]
    fn the_space_is_never_wrapped() {
        let mut state = SequenceState {
            last_accepted: u64::MAX - 1,
        };
        assert_eq!(state.next_for_send(), Ok(u64::MAX));
        assert_eq!(state.next_for_send(), Err(SequenceRefusal::Exhausted));
        assert_eq!(state.accept(0), Err(SequenceRefusal::Exhausted));
        assert_eq!(state.expected(), None);
    }
}
