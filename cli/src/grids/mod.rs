//! One namespace for the four grids.
//!
//! `yougori grids NOUN VERB [TARGET] [--grid NAME]` is one way of asking all four products the
//! same kinds of question: who is in this grid, which computers belong to it, what it is running,
//! what it holds and what it recorded. Twelve wire methods carry it, one per noun, with the verb
//! inside the request, which is the shape `desks_manage`, `access_manage`, `swarm_dispatch` and
//! `bounty_dispatch` already use.
//!
//! Nothing here replaces a word anybody types today. Every command the four products shipped
//! keeps working, through its own parser and its own wire method, unchanged. This is a second
//! door onto the same product code, never a rewrite of it: forwarding the old methods through the
//! new one would change what a shipped client does, and that is not allowed.
//!
//! The command model lives in the CLI crate because `src-tauri` already depends on it while this
//! crate depends on neither the grid crate nor Tauri, so one table describes the namespace for
//! the terminal and the engine at once.

pub mod alias;
pub mod answer;
pub mod fault;
pub mod render;
pub mod run;
pub mod words;

use fault::{Code, Fault};

/// What a grid does. The same four the core's own `realm::Capability` has, in the same words;
/// a test compares the two lists so they cannot drift.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Capability {
    Models,
    Workspaces,
    Credentials,
    Research,
}

impl Capability {
    /// The word the core writes down and the wire carries.
    pub fn word(self) -> &'static str {
        match self {
            Capability::Models => "models",
            Capability::Workspaces => "workspaces",
            Capability::Credentials => "credentials",
            Capability::Research => "research",
        }
    }

    /// The same capability as something a grid does, for a sentence that needs a verb.
    pub fn doing(self) -> &'static str {
        match self {
            Capability::Models => "serve models",
            Capability::Workspaces => "host workspaces",
            Capability::Credentials => "broker credentials",
            Capability::Research => "run authorised research",
        }
    }

    /// The words a person types for `--serve`, which are the words the products use for
    /// themselves: a Sandbox Grid hosts desks, and the core calls that workspaces.
    pub fn from_word(word: &str) -> Option<Capability> {
        match word {
            "models" | "model" | "neo" => Some(Capability::Models),
            "workspaces" | "workspace" | "desks" | "desk" => Some(Capability::Workspaces),
            "credentials" | "credential" | "access" => Some(Capability::Credentials),
            "research" | "bounty" | "bounties" => Some(Capability::Research),
            _ => None,
        }
    }

    pub fn all() -> &'static [Capability] {
        &[Capability::Models, Capability::Workspaces, Capability::Credentials, Capability::Research]
    }
}

/// Which hub actually answers today. Every one of these is a product that ships; `Core` is what
/// each becomes as its phase lands, and nothing reports it yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Product {
    /// Closed Neo Grid: models on the company's own computers.
    Neo,
    /// Sandbox Grid: desks for named people on the company's computers.
    Desks,
    /// Access Grid: company credentials agents use without seeing them.
    Access,
    /// Closed Bounty: a company's own bounty, hosted here.
    Bounty,
}

impl Product {
    pub fn capability(self) -> Capability {
        match self {
            Product::Neo => Capability::Models,
            Product::Desks => Capability::Workspaces,
            Product::Access => Capability::Credentials,
            Product::Bounty => Capability::Research,
        }
    }
    /// Which product serves one thing, for a grid that does not exist to be looked up yet. This
    /// is `capability()` read the other way round, and a test holds the two to each other.
    pub fn serving(capability: Capability) -> Product {
        match capability {
            Capability::Models => Product::Neo,
            Capability::Workspaces => Product::Desks,
            Capability::Credentials => Product::Access,
            Capability::Research => Product::Bounty,
        }
    }
    /// What this grid is called in the sidebar and in everything a person reads.
    pub fn product_name(self) -> &'static str {
        match self {
            Product::Neo => "Closed Neo Grid",
            Product::Desks => "Sandbox Grid",
            Product::Access => "Access Grid",
            Product::Bounty => "Closed Bounty",
        }
    }
    /// The short word `--grid` takes when a grid has no company name of its own yet.
    pub fn handle(self) -> &'static str {
        match self {
            Product::Neo => "models",
            Product::Desks => "desks",
            Product::Access => "credentials",
            Product::Bounty => "research",
        }
    }
    pub fn kind(self) -> &'static str {
        match self {
            Product::Bounty => "research",
            _ => "primary",
        }
    }
    pub fn all() -> &'static [Product] {
        &[Product::Neo, Product::Desks, Product::Access, Product::Bounty]
    }
}

/// The twelve nouns, one wire method each.
pub const NOUNS: [&str; 12] = [
    "realm",
    "people",
    "computers",
    "share",
    "models",
    "desks",
    "credentials",
    "requests",
    "research",
    "connectors",
    "work",
    "log",
];

/// The wire method for a noun.
pub fn method_for(noun: &str) -> Option<&'static str> {
    NOUNS.iter().position(|known| *known == noun).map(|index| METHODS[index])
}

/// The noun a wire method is about.
pub fn noun_for(method: &str) -> Option<&'static str> {
    METHODS.iter().position(|known| *known == method).map(|index| NOUNS[index])
}

/// Every wire method in this namespace. Each of these has a catalog entry, a dispatch arm and a
/// row in `cli/src/help_coverage.rs`, and a test refuses to pass without all three.
pub const METHODS: [&str; 12] = [
    "grids_realm",
    "grids_people",
    "grids_computers",
    "grids_share",
    "grids_models",
    "grids_desks",
    "grids_credentials",
    "grids_requests",
    "grids_research",
    "grids_connectors",
    "grids_work",
    "grids_log",
];

/// One verb of one noun: what it needs the grid to do, whether it writes, what it is asked to
/// confirm, and which words and options it takes.
///
/// This one table is what the terminal parses with, what `yougori grids NOUN --help` prints,
/// what the engine refuses with, and what the launcher's submenu is built from. There is no
/// second list anywhere that could disagree with it.
#[derive(Clone, Copy, Debug)]
pub struct Verb {
    pub noun: &'static str,
    pub verb: &'static str,
    /// The grid must do at least one of these for the command to mean anything. Empty means the
    /// command is about the grid itself and needs nothing turned on.
    pub needs: &'static [Capability],
    pub mutating: bool,
    /// The sentence a person is shown before a change that cannot simply be undone.
    pub confirmation: Option<&'static str>,
    /// Words typed after the verb, in order, and what each is called in the request.
    pub targets: &'static [&'static str],
    /// Options this verb takes, without their leading dashes.
    pub options: &'static [&'static str],
    /// One line for the help.
    pub says: &'static str,
}

macro_rules! verb {
    ($noun:literal, $verb:literal, $needs:expr, $write:expr, $confirm:expr, $targets:expr, $options:expr, $says:literal) => {
        Verb { noun: $noun, verb: $verb, needs: $needs, mutating: $write, confirmation: $confirm, targets: $targets, options: $options, says: $says }
    };
}

const ANY: &[Capability] = &[];
const MODELS: &[Capability] = &[Capability::Models];
const DESKS: &[Capability] = &[Capability::Workspaces];
const CREDENTIALS: &[Capability] = &[Capability::Credentials];
const RESEARCH: &[Capability] = &[Capability::Research];
const PEOPLE_IN: &[Capability] = &[Capability::Workspaces, Capability::Credentials];
const COMPUTERS_IN: &[Capability] = &[Capability::Models, Capability::Workspaces, Capability::Research];
const SHARE_IN: &[Capability] = &[Capability::Models, Capability::Workspaces];

/// Every verb in the namespace.
pub const VERBS: &[Verb] = &[
    // The grid itself. These are typed without a noun, because `grids realm status` reads badly.
    verb!("realm", "list", ANY, false, None, &[], &[], "Every grid on this computer"),
    verb!("realm", "status", ANY, false, None, &[], &["full"], "One grid, or all of them"),
    // Health is about this computer's grids rather than about one of them, so it is answered by
    // the engine's own register like `list` is, and it needs no capability: an operator asking
    // whether a grid is healthy must never be refused because of what that grid is for.
    verb!("realm", "health", ANY, false, None, &[], &["full"], "Whether this computer's grids are healthy"),
    verb!("realm", "observe", ANY, true, None, &[], &["port", "off"], "Serve health and a reading to a monitoring agent on this computer"),
    verb!("realm", "address", ANY, false, None, &[], &[], "This computer's address to host on"),
    verb!("realm", "new", ANY, true, Some("Starts a grid on this computer and makes this computer its hub."), &["name"], &["serve", "ip", "tunnel", "password", "port", "hostname", "username", "person-name", "title", "instructions", "authorization", "source"], "Start a grid here"),
    verb!("realm", "join", ANY, true, None, &["name"], &["serve", "invite", "password", "person-name", "ip", "port", "fingerprint", "file", "ready-made"], "Join a grid somebody else runs"),
    verb!("realm", "password", ANY, true, Some("Changes the grid's password; every computer has to be told the new one."), &[], &["password"], "Change the grid's password"),
    verb!("realm", "leave", ANY, true, Some("Takes this computer out of the grid."), &[], &[], "Leave the grid"),
    verb!("realm", "delete", ANY, true, Some("Deletes the grid this computer runs."), &[], &["when"], "Delete the grid this computer runs"),
    verb!("realm", "restore", ANY, true, None, &[], &[], "Undo a deletion that is waiting"),
    verb!("realm", "backup", CREDENTIALS, true, None, &[], &["output", "passphrase"], "Write a backup of the grid"),
    verb!("realm", "restore-backup", CREDENTIALS, true, Some("Replaces this computer's grid with the one in the backup file."), &["file"], &["passphrase", "ip"], "Put a backup back"),
    verb!("realm", "settings", CREDENTIALS, true, None, &[], &["require-two-step"], "Change what the grid insists on"),
    verb!("realm", "manage", ANY, true, Some("Sends an administrator's request straight to the grid."), &[], &["file"], "The administrator's raw door, from a private file"),
    // People.
    verb!("people", "list", PEOPLE_IN, false, None, &[], &[], "Everyone in the grid"),
    verb!("people", "show", PEOPLE_IN, false, None, &["person"], &[], "One person"),
    verb!("people", "add", PEOPLE_IN, true, None, &["person"], &["person-name", "email", "permission", "teams", "password", "size", "kind", "cpu", "memory-gb", "disk-gb", "gpu"], "Add a person"),
    verb!("people", "set", PEOPLE_IN, true, None, &["person"], &["person-name", "email", "permission", "teams"], "Change a person's details"),
    verb!("people", "password", PEOPLE_IN, true, Some("Changes this person's password; they are signed out everywhere."), &["person"], &["password"], "Set a person's password"),
    verb!("people", "remove", PEOPLE_IN, true, Some("Removes this person and everything that was theirs."), &["person"], &[], "Remove a person"),
    verb!("people", "sign-in", PEOPLE_IN, true, None, &[], &["invite", "person", "password", "code", "sso"], "Sign in from this computer"),
    verb!("people", "sign-out", PEOPLE_IN, true, Some("Ends the session on this computer, or this person's sessions everywhere."), &["person"], &[], "Sign out"),
    verb!("people", "sign-out-others", PEOPLE_IN, true, Some("Ends this person's sessions on every other computer."), &[], &[], "Sign out every other computer"),
    verb!("people", "two-step", CREDENTIALS, true, None, &["step"], &["code"], "Turn your own two-step sign-in on or off"),
    verb!("people", "reset-two-step", PEOPLE_IN, true, Some("Takes two-step sign-in off this person's account until they set it up again."), &["person"], &[], "Reset somebody's two-step sign-in"),
    verb!("people", "my-password", CREDENTIALS, true, None, &[], &["password", "code"], "Change your own password"),
    verb!("people", "sso", PEOPLE_IN, true, Some("Changes how everybody signs in to this grid."), &[], &["issuer", "client-id", "claim", "redirect-port", "passwordless", "off"], "Sign-in through the company's identity provider"),
    // Computers that belong to a grid.
    verb!("computers", "list", COMPUTERS_IN, false, None, &[], &[], "Which computers belong to the grid"),
    verb!("computers", "show", COMPUTERS_IN, false, None, &["computer"], &[], "One computer"),
    verb!("computers", "remove", COMPUTERS_IN, true, Some("Takes this computer out of the grid and stops what it was running."), &["computer"], &[], "Remove a computer"),
    verb!("computers", "forget", CREDENTIALS, true, Some("Makes this computer sign in again next time."), &["device"], &[], "Forget a remembered computer"),
    verb!("computers", "cloud-fallback", DESKS, true, Some("Changes where desks are built when no company computer has room."), &["step"], &["file"], "Where desks go when the company's computers are full"),
    // What an enrolled computer gives the grid.
    verb!("share", "show", SHARE_IN, false, None, &["computer"], &[], "What one computer gives the grid"),
    verb!("share", "set", SHARE_IN, true, None, &["computer"], &["cpu", "memory-gb", "disk-gb", "gpu", "idle-only", "suggested"], "Set what a computer gives"),
    verb!("share", "drain", SHARE_IN, true, Some("Stops giving this computer's share to the grid."), &["computer"], &[], "Stop using a computer"),
    verb!("share", "bring-back", SHARE_IN, true, None, &["computer"], &[], "Use a computer again"),
    // Models.
    verb!("models", "list", MODELS, false, None, &[], &[], "Which models the grid runs"),
    verb!("models", "show", MODELS, false, None, &["plan"], &[], "One model plan"),
    verb!("models", "add", MODELS, true, None, &[], &["model", "percent", "schedule", "idle-after", "quant", "scope", "computers"], "Run a model across the grid"),
    verb!("models", "set", MODELS, true, None, &["plan"], &["model", "percent", "schedule", "idle-after", "quant"], "Change a model plan"),
    verb!("models", "remove", MODELS, true, Some("Stops running this model on the grid's computers."), &["plan"], &[], "Drop a model plan"),
    verb!("models", "add-team", MODELS, true, None, &[], &["team", "lead", "workers", "computers", "strategy", "tasks", "rounds"], "Define a team of models that answer one call"),
    verb!("models", "remove-team", MODELS, true, Some("Removes this team of models."), &["team"], &[], "Remove a team"),
    verb!("models", "run-team", MODELS, true, None, &["team"], &["prompt"], "Run a team once"),
    verb!("models", "add-key", MODELS, true, None, &[], &["app"], "Make an API key for an app"),
    verb!("models", "revoke-key", MODELS, true, Some("Stops this API key working at once."), &["key"], &[], "Revoke an API key"),
    // GPUs rented in NeoCloud, working in this grid. Two of these end work somebody is paying
    // for by the hour, so both carry a confirmation.
    verb!("models", "gpus", MODELS, false, None, &[], &[], "Rented GPUs working in this grid"),
    verb!("models", "add-gpu", MODELS, true, None, &["gpu"], &[], "Put a GPU you have rented to work in the grid"),
    verb!("models", "remove-gpu", MODELS, true, Some("Takes this rented GPU out of the grid and stops its pod, ending its hourly charge."), &["gpu"], &[], "Take a rented GPU out and stop it"),
    verb!("models", "stop-gpus", MODELS, true, Some("Stops every rented GPU in the grid, ending their hourly charges."), &[], &[], "Stop every rented GPU in the grid"),
    // Desks.
    verb!("desks", "list", DESKS, false, None, &[], &[], "Every desk in the grid"),
    verb!("desks", "show", DESKS, false, None, &["desk"], &[], "One desk"),
    verb!("desks", "mine", DESKS, false, None, &[], &[], "This person's own desk"),
    verb!("desks", "add", DESKS, true, None, &["desk"], &["person", "kind", "cpu", "memory-gb", "disk-gb", "gpu", "image", "size"], "Order a desk"),
    verb!("desks", "assign", DESKS, true, None, &["desk"], &["person"], "Give a desk to somebody"),
    verb!("desks", "retry", DESKS, true, None, &["desk"], &[], "Build a desk again after a failure"),
    verb!("desks", "remove", DESKS, true, Some("Removes this desk and the work on it."), &["desk"], &[], "Remove a desk"),
    verb!("desks", "sign-in", DESKS, true, None, &[], &["invite", "person", "password", "code", "sso"], "Sign in to your desk from any computer"),
    verb!("desks", "refresh", DESKS, true, None, &[], &[], "Refresh this computer's desk session"),
    verb!("desks", "sign-out", DESKS, true, Some("Ends this computer's desk session."), &[], &[], "Sign out of your desk"),
    verb!("desks", "portal", DESKS, false, None, &[], &[], "The address a person opens their desk at"),
    verb!("desks", "add-image", DESKS, true, None, &[], &["image", "from", "sha256"], "Offer a prepared disk image"),
    verb!("desks", "import-image", DESKS, true, None, &[], &["path", "image"], "Take in a disk image from this computer"),
    verb!("desks", "remove-image", DESKS, true, Some("Removes this image; desks already built from it are untouched."), &["image"], &[], "Remove a disk image"),
    verb!("desks", "add-size", DESKS, true, None, &["size"], &["kind", "cpu", "memory-gb", "disk-gb", "gpu", "image"], "Name a size of desk"),
    verb!("desks", "remove-size", DESKS, true, Some("Removes this size of desk from the catalogue."), &["size"], &[], "Remove a size of desk"),
    verb!("desks", "parking", DESKS, true, Some("Changes where a desk's data is parked when its computer goes away."), &["step"], &["file"], "Where a desk's data waits"),
    // Credentials.
    verb!("credentials", "list", CREDENTIALS, false, None, &[], &[], "Which credentials the grid holds"),
    verb!("credentials", "show", CREDENTIALS, false, None, &["credential"], &[], "One credential, without its value"),
    verb!("credentials", "add", CREDENTIALS, true, None, &["credential"], &["kind", "destination", "field", "note", "value", "config"], "Add a credential"),
    verb!("credentials", "set", CREDENTIALS, true, None, &["credential"], &["credential-name", "kind", "destination", "field", "note", "config"], "Change a credential"),
    verb!("credentials", "rotate", CREDENTIALS, true, Some("Replaces this credential's value; anything using the old one stops."), &["credential"], &["value"], "Give a credential a new value"),
    verb!("credentials", "remove", CREDENTIALS, true, Some("Removes this credential and every rule about it."), &["credential"], &[], "Remove a credential"),
    verb!("credentials", "allow", CREDENTIALS, true, None, &["credential"], &["who", "methods", "path", "ask", "never", "reveal", "limit", "hours", "note"], "Say who may use a credential, and how"),
    verb!("credentials", "remove-rule", CREDENTIALS, true, Some("Removes this rule; whoever it allowed stops being allowed."), &["rule"], &[], "Remove a rule"),
    verb!("credentials", "use", CREDENTIALS, true, None, &["credential", "url"], &["request-method", "header", "body", "body-file", "agent"], "Make one call with a credential nobody sees"),
    verb!("credentials", "reveal", CREDENTIALS, true, Some("Shows a credential's value to whoever asked for it."), &["credential"], &["reason", "agent"], "Ask to see a credential's value"),
    // Approvals.
    verb!("requests", "list", CREDENTIALS, false, None, &[], &[], "What is waiting for somebody to agree"),
    verb!("requests", "show", CREDENTIALS, false, None, &["request"], &[], "One waiting request"),
    verb!("requests", "approve", CREDENTIALS, true, None, &["request"], &["hours"], "Agree to a request"),
    verb!("requests", "deny", CREDENTIALS, true, None, &["request"], &["reason"], "Refuse a request"),
    verb!("requests", "check", CREDENTIALS, false, None, &["request"], &[], "Whether a request has been decided"),
    // Research.
    verb!("research", "list", RESEARCH, false, None, &[], &[], "The research workers on this computer"),
    verb!("research", "show", RESEARCH, false, None, &["worker"], &[], "One worker"),
    verb!("research", "check", RESEARCH, false, None, &["worker"], &[], "Whether a worker is able to run"),
    verb!("research", "activity", RESEARCH, false, None, &["worker"], &["after"], "What a worker has been doing"),
    verb!("research", "offers", RESEARCH, false, None, &["worker"], &[], "What a worker has been offered"),
    verb!("research", "details", RESEARCH, false, None, &["worker", "offer"], &[], "One offer in full"),
    verb!("research", "skip", RESEARCH, true, None, &["worker", "offer"], &[], "Pass on an offer"),
    verb!("research", "bounties", RESEARCH, false, None, &["worker"], &[], "Published bounties"),
    verb!("research", "rewards", RESEARCH, false, None, &["worker"], &[], "What a worker has been paid"),
    verb!("research", "reports", RESEARCH, false, None, &["worker"], &[], "A worker's reports"),
    verb!("research", "messages", RESEARCH, false, None, &["worker"], &[], "What a worker said"),
    verb!("research", "chat", RESEARCH, true, None, &["worker"], &["message"], "Say something to a worker"),
    verb!("research", "pause", RESEARCH, true, None, &["worker"], &[], "Pause a worker"),
    verb!("research", "resume", RESEARCH, true, None, &["worker"], &["budget-minutes"], "Let a worker carry on"),
    verb!("research", "stop", RESEARCH, true, Some("Stops this worker; work in progress is lost."), &["worker"], &[], "Stop a worker"),
    verb!("research", "leave", RESEARCH, true, Some("Leaves this bounty; the publisher is told."), &["worker"], &[], "Leave a bounty"),
    verb!("research", "remove", RESEARCH, true, Some("Removes this worker and everything it kept."), &["worker"], &[], "Remove a worker"),
    verb!("research", "memory", RESEARCH, true, None, &["worker", "step"], &[], "Keep or release what a worker remembers"),
    // Connectors into systems somebody else runs.
    verb!("connectors", "list", DESKS, false, None, &[], &[], "Which systems the grid reaches"),
    verb!("connectors", "show", DESKS, false, None, &["connector"], &[], "One connector"),
    verb!("connectors", "add", DESKS, true, None, &[], &["file"], "Add a connector, from a private file"),
    verb!("connectors", "credential", DESKS, true, None, &["connector"], &["file"], "Give a connector its credential, from a private file"),
    verb!("connectors", "test", DESKS, true, None, &["connector"], &[], "Sign in and say what it reaches"),
    verb!("connectors", "provision", DESKS, true, None, &["connector"], &["person"], "Give a person an account there"),
    verb!("connectors", "revoke", DESKS, true, Some("Takes this person's account there away."), &["connector"], &["person"], "Take an account back"),
    verb!("connectors", "remove", DESKS, true, Some("Removes this connector; accounts it made stay as they are."), &["connector"], &[], "Remove a connector"),
    // The engine's own record of the work a command queued.
    verb!("work", "list", ANY, false, None, &[], &[], "What this computer has been asked to do"),
    verb!("work", "show", ANY, false, None, &["work"], &[], "One piece of work"),
    verb!("work", "cancel", ANY, true, Some("Cancels this work; what it already did is not undone."), &["work"], &[], "Cancel work"),
    // The record.
    verb!("log", "show", ANY, false, None, &[], &["since", "limit", "command"], "What the grid recorded"),
    verb!("log", "export", CREDENTIALS, true, None, &[], &["output", "limit"], "Carry the record out to a file"),
    verb!("log", "verify", ANY, false, None, &[], &[], "Whether the record is whole"),
];

/// One verb of one noun, by its words.
pub fn find(noun: &str, verb: &str) -> Option<&'static Verb> {
    VERBS.iter().find(|known| known.noun == noun && known.verb == verb)
}

/// Every verb of one noun, for the help and for the launcher's submenu.
pub fn verbs_of(noun: &str) -> Vec<&'static Verb> {
    VERBS.iter().filter(|known| known.noun == noun).collect()
}

/// Whether a grid that does these things may be asked this at all.
pub fn admissible(verb: &Verb, does: &[Capability]) -> Result<(), Fault> {
    if verb.needs.is_empty() || verb.needs.iter().any(|needed| does.contains(needed)) {
        return Ok(());
    }
    let missing: Vec<&str> = verb.needs.iter().map(|capability| capability.doing()).collect();
    Err(Fault::new(Code::CapabilityOff, format!("This grid does not {}.", join_words(&missing))))
}

/// `a`, `a or b`, `a, b or c`.
pub fn join_words(words: &[&str]) -> String {
    match words {
        [] => String::new(),
        [one] => (*one).to_owned(),
        [first @ .., last] => format!("{} or {last}", first.join(", ")),
    }
}

/// Whether this is a command of the new namespace at all.
pub fn requested(args: &[String]) -> bool {
    args.first().is_some_and(|word| word == "grids")
}

#[cfg(test)]
mod tests;
