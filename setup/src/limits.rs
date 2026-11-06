//! The bounds every client and the website apply to packages and expanded plans.
//!
//! One place for every number, so the CLI, the desktop, the engine and the website refuse the
//! same thing with the same words. A refusal names the limit it hit and the count that hit it.

/// One bound and the words a message uses for it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limit {
    /// What is counted, as a message says it: "resources in a plan".
    pub what: &'static str,
    pub max: usize,
}

impl Limit {
    pub const fn new(what: &'static str, max: usize) -> Limit {
        Limit { what, max }
    }

    pub fn allows(self, count: usize) -> bool {
        count <= self.max
    }

    /// The refusal for `count`, naming the limit.
    pub fn exceeded(self, count: usize) -> String {
        format!("Too many {}: {count}, and the limit is {}.", self.what, self.max)
    }
}

// Graphs and conditions (plan section 7.4).
pub const DEPENDENCY_DEPTH: Limit = Limit::new("levels of dependencies", 8);
pub const RESOURCES: Limit = Limit::new("resources in a plan", 256);
pub const EDGES: Limit = Limit::new("dependency edges in a plan", 512);
pub const DEPENDS_ON: Limit = Limit::new("dependencies of one resource", 32);
pub const CONDITION_DEPTH: Limit = Limit::new("levels in a condition", 8);
pub const CONDITION_TERMS: Limit = Limit::new("conditions under all or any", 32);
pub const CONDITION_VALUES: Limit = Limit::new("answers in one condition", 12);

// Templates.
pub const INPUTS: Limit = Limit::new("inputs", 50);
pub const CHOICES: Limit = Limit::new("choices of one input", 12);
pub const CAPABILITIES: Limit = Limit::new("capabilities", 64);
pub const IMPORTS: Limit = Limit::new("imports", 16);
pub const IMPORT_DEPTH: Limit = Limit::new("levels of imports", 1);
pub const ALIASES: Limit = Limit::new("aliases", 16);
pub const ALIAS_CHARS: Limit = Limit::new("characters in an alias", 64);
pub const VIEWS: Limit = Limit::new("views", 16);
pub const STEPS: Limit = Limit::new("steps", 20);
pub const OUTPUTS: Limit = Limit::new("outputs", 20);
pub const TOPICS: Limit = Limit::new("topics", 10);
pub const INSTALL_LINES: Limit = Limit::new("install lines of a tool", 32);
pub const COMMAND_PARTS: Limit = Limit::new("parts of a command", 64);
pub const CREDENTIALS: Limit = Limit::new("credentials of one broker", 256);
pub const COMPUTERS: Limit = Limit::new("selected computers of one pool", 64);
pub const WORKERS: Limit = Limit::new("workers of one group", 256);
pub const REPLICAS: Limit = Limit::new("replicas of one model", 64);
pub const WORKSPACES: Limit = Limit::new("workspaces of one pool", 1024);
pub const RETRIES: Limit = Limit::new("attempts of one job", 10);
pub const JOB_SECONDS: Limit = Limit::new("seconds a job may run", 7 * 24 * 3600);

// Text.
pub const ID_CHARS: Limit = Limit::new("characters in an id", 32);
pub const NAME_CHARS: Limit = Limit::new("characters in a name", 64);
pub const TITLE_CHARS: Limit = Limit::new("characters in a title", 80);
pub const SUBTITLE_CHARS: Limit = Limit::new("characters in a subtitle", 120);
pub const SUMMARY_CHARS: Limit = Limit::new("characters in a summary", 200);
pub const QUESTION_CHARS: Limit = Limit::new("characters in a question", 200);
pub const HINT_CHARS: Limit = Limit::new("characters in a hint", 160);
pub const LABEL_CHARS: Limit = Limit::new("characters in a label", 60);
pub const CHANGELOG_CHARS: Limit = Limit::new("characters in a changelog", 4000);
pub const TEXT_ANSWER_CHARS: Limit = Limit::new("characters in a text answer", 500);
pub const SECRET_BYTES: Limit = Limit::new("bytes in a secret", 65536);
pub const SHELL_LINE_CHARS: Limit = Limit::new("characters in a shell line", 4096);
pub const STEP_TITLE_CHARS: Limit = Limit::new("characters in a step title", 120);
pub const STEP_DETAIL_CHARS: Limit = Limit::new("characters in a step detail", 500);
pub const STEP_COMMAND_CHARS: Limit = Limit::new("characters in a step command", 500);
pub const OUTPUT_VALUE_CHARS: Limit = Limit::new("characters in an output", 500);
pub const SIGNIN_HINT_CHARS: Limit = Limit::new("characters in a sign-in hint", 500);

// Reviews, as the website stores them (plan section 17.2).
pub const REVIEW_TEXT: Limit = Limit::new("characters in a review text", 4000);
pub const REVIEW_DEPTH: Limit = Limit::new("levels of nesting in a review", 4);
pub const REVIEW_BYTES: Limit = Limit::new("bytes in a review", 128 * 1024);
pub const REVIEW_COSTS: Limit = Limit::new("costs in a review", 32);

// Packages.
pub const MANIFEST_BYTES: Limit = Limit::new("bytes in a template file", 64 * 1024);
/// Counted with aliases expanded, so one anchor repeated many times can't grow a small file
/// into millions of values.
pub const YAML_VALUES: Limit = Limit::new("values in one YAML file, counting each alias in full", 100_000);
pub const PROJECT_BYTES: Limit = Limit::new("bytes in a project file", 1024 * 1024);
pub const FILES: Limit = Limit::new("files in a package", 1000);
pub const FILE_BYTES: Limit = Limit::new("bytes in one file", 5 * 1024 * 1024);
pub const PACKAGE_BYTES: Limit = Limit::new("bytes in a package", 25 * 1024 * 1024);
pub const PATH_CHARS: Limit = Limit::new("characters in a path", 512);
pub const PATH_PART_CHARS: Limit = Limit::new("characters in a file or folder name", 255);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_names_the_limit_and_the_count() {
        assert!(RESOURCES.allows(256) && !RESOURCES.allows(257));
        assert_eq!(RESOURCES.exceeded(300), "Too many resources in a plan: 300, and the limit is 256.");
        assert_eq!(DEPENDENCY_DEPTH.max, 8);
        assert_eq!(EDGES.max, 512);
        assert_eq!(CONDITION_DEPTH.max, 8);
    }
}
