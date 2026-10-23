//! Refusals that are sentences, with a code travelling beside them.
//!
//! The rule this file exists to hold: the sentence is the error, and the code is a separate
//! field. A person is shown the sentence and never the code; a script reads both. Nothing here
//! guesses a code from the wording of a sentence, which is the coupling this replaces.

use crate::wire;

/// What went wrong, as a machine reads it. Every one of these has a sentence beside it; none of
/// them is ever shown to a person on its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Code {
    // Naming the grid
    NoSuchGrid,
    GridNotNamed,
    GridNotOpen,
    NotOnThisComputer,
    // Permission
    CapabilityOff,
    NotAllowed,
    NeedsConfirmation,
    // Finding the thing
    NoSuchThing,
    // The words typed
    UnknownWords,
    MissingWords,
    ValueUnusable,
    SecretInArguments,
    // The record
    NotYetOnThisDoor,
    GridRefused,
}

impl Code {
    /// The machine's name for it: lower case with underscores, like every other code the wire
    /// already carries.
    pub fn slug(self) -> &'static str {
        match self {
            Code::NoSuchGrid => "no_such_grid",
            Code::GridNotNamed => "grid_not_named",
            Code::GridNotOpen => "grid_not_open",
            Code::NotOnThisComputer => "not_on_this_computer",
            Code::CapabilityOff => "capability_off",
            Code::NotAllowed => "not_allowed",
            Code::NeedsConfirmation => "needs_confirmation",
            Code::NoSuchThing => "no_such_thing",
            Code::UnknownWords => "unknown_words",
            Code::MissingWords => "missing_words",
            Code::ValueUnusable => "value_unusable",
            Code::SecretInArguments => "secret_in_arguments",
            Code::NotYetOnThisDoor => "not_yet_on_this_door",
            Code::GridRefused => "grid_refused",
        }
    }

    /// Whether trying the same thing again could work.
    pub fn retryable(self) -> bool {
        false
    }

    /// What the wire's `outcome` field says happened. Everything here is refused before the
    /// grid is changed, so nothing was started.
    pub fn outcome(self) -> &'static str {
        "not_started"
    }

    pub fn all() -> &'static [Code] {
        &[
            Code::NoSuchGrid,
            Code::GridNotNamed,
            Code::GridNotOpen,
            Code::NotOnThisComputer,
            Code::CapabilityOff,
            Code::NotAllowed,
            Code::NeedsConfirmation,
            Code::NoSuchThing,
            Code::UnknownWords,
            Code::MissingWords,
            Code::ValueUnusable,
            Code::SecretInArguments,
            Code::NotYetOnThisDoor,
            Code::GridRefused,
        ]
    }

    pub fn from_slug(slug: &str) -> Option<Code> {
        Code::all().iter().copied().find(|code| code.slug() == slug)
    }
}

/// One refusal: what a person is told, and what a script reads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fault {
    pub code: Code,
    /// One sentence for a person. Never the code, never an identifier.
    pub said: String,
    /// What it is about, by the name a person would use.
    pub about: Option<String>,
}

/// How a grids refusal travels over a wire whose handlers hand back a string.
///
/// `queue::handle` already strips prefixes of this shape for the engine's own conditions
/// (`YOUGORI_BUSY`, `YOUGORI_QUIESCING`), so this is the arrangement that is there rather than a
/// new one. The queue takes the code off and puts it in `errorDetails`; what is left is the
/// sentence, which is the only thing a terminal prints.
pub const PREFIX: &str = "YOUGORI_GRIDS";

impl Fault {
    pub fn new(code: Code, said: impl Into<String>) -> Fault {
        Fault { code, said: said.into(), about: None }
    }

    pub fn about(mut self, which: &str) -> Fault {
        self.about = Some(which.to_owned());
        self
    }

    /// The one string a handler hands back, with the code in front of the sentence for the queue
    /// to take off again.
    pub fn wire(&self) -> String {
        match &self.about {
            Some(about) => format!("{PREFIX} {} {about}: {}", self.code.slug(), self.said),
            None => format!("{PREFIX} {}: {}", self.code.slug(), self.said),
        }
    }

    /// Reads back what `wire` wrote. Anything that is not one of these is left alone, so an
    /// ordinary failure from a product handler keeps its own sentence and its guessed code.
    pub fn read(message: &str) -> Option<(String, wire::ErrorDetails)> {
        let rest = message.strip_prefix(PREFIX)?.trim_start();
        let (head, said) = rest.split_once(": ")?;
        let (slug, about) = head.split_once(' ').map_or((head, None), |(slug, about)| (slug, Some(about.to_owned())));
        let code = Code::from_slug(slug)?;
        Some((
            said.to_owned(),
            wire::ErrorDetails {
                code: code.slug().to_owned(),
                affected_resource: about,
                retryable: code.retryable(),
                outcome: code.outcome().to_owned(),
            },
        ))
    }

    /// What a script reads beside the sentence.
    pub fn details(&self) -> wire::ErrorDetails {
        wire::ErrorDetails {
            code: self.code.slug().to_owned(),
            affected_resource: self.about.clone(),
            retryable: self.code.retryable(),
            outcome: self.code.outcome().to_owned(),
        }
    }

    /// The muted line `--explain` adds under the sentence, and nothing prints without it.
    pub fn explained(&self) -> String {
        format!("Code: {} - trying again would {}", self.code.slug(), if self.code.retryable() { "be worth it" } else { "not help" })
    }
}

impl From<Fault> for String {
    fn from(fault: Fault) -> String {
        fault.wire()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_travels_beside_a_sentence_and_never_instead_of_one() {
        for code in Code::all() {
            let fault = Fault::new(*code, "This grid does not hold credentials.").about("Acme");
            let (said, details) = Fault::read(&fault.wire()).expect("a grids refusal reads back");
            assert_eq!(said, "This grid does not hold credentials.");
            assert_eq!(details.code, code.slug());
            assert_eq!(details.affected_resource.as_deref(), Some("Acme"));
            assert_eq!(details.outcome, code.outcome());
            // The sentence a person sees carries no code and no underscore.
            assert!(!said.contains('_') && !said.contains(code.slug()));
        }
    }

    #[test]
    fn an_ordinary_product_failure_is_left_exactly_as_it_was() {
        assert!(Fault::read("This computer does not run a grid hub").is_none());
        assert!(Fault::read("YOUGORI_BUSY: another change is running").is_none());
        assert!(Fault::read("YOUGORI_GRIDS not_a_code: hello").is_none());
    }

    #[test]
    fn every_code_has_one_slug_and_reads_back_to_itself() {
        let mut slugs = std::collections::BTreeSet::new();
        for code in Code::all() {
            assert!(slugs.insert(code.slug()), "two codes share the slug {}", code.slug());
            assert_eq!(Code::from_slug(code.slug()), Some(*code));
            assert!(code.slug().chars().all(|c| c.is_ascii_lowercase() || c == '_'));
        }
    }
}
