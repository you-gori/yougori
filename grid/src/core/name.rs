//! Names a person can read aloud.
//!
//! Everything a person is shown should have a name they can repeat down a telephone. Identifiers
//! belong in JSON, where a machine reads them. One typed command gets one of these, and every
//! event that command causes carries it, so "what did keen heron three f one a do" is a question
//! somebody can actually ask.
//!
//! A command name and a Swarm Mining worker name must never be mistaken for one another, so they
//! are told apart by shape rather than by context: a worker is two words, a command is two words
//! and four hexadecimal digits. `is_command` is that rule, written once.

/// The first word. Plain, ordinary English; nothing that reads as a judgement about a person.
pub const ADJECTIVES: [&str; 48] = [
    "amber", "ancient", "bold", "brave", "bright", "brisk", "calm", "clear", "clever", "cosy",
    "crisp", "curious", "daring", "eager", "early", "easy", "fair", "fond", "frank", "gentle",
    "glad", "golden", "grand", "happy", "hardy", "keen", "kind", "lively", "lucky", "merry",
    "mild", "noble", "patient", "plain", "polite", "proud", "quiet", "rapid", "ready", "shy",
    "silver", "snowy", "steady", "sunny", "swift", "tidy", "warm", "wise",
];

/// The second word. Creatures and ordinary things, nothing a person could read as being about
/// them or their work.
pub const NOUNS: [&str; 48] = [
    "acorn", "anchor", "badger", "beacon", "birch", "bison", "bramble", "cedar", "comet", "coral",
    "crane", "dolphin", "ember", "falcon", "fern", "ferry", "fjord", "garnet", "harbour", "harvest",
    "hazel", "heron", "island", "ivy", "juniper", "kestrel", "lantern", "linnet", "maple", "meadow",
    "mint", "orchard", "otter", "owl", "pebble", "pine", "puffin", "quarry", "raven", "ridge",
    "robin", "sable", "sparrow", "thistle", "willow", "wren", "yarrow", "zephyr",
];

/// A name from a number: two words and four hexadecimal digits, such as `keen-heron-3f1a`.
///
/// The same number always gives the same name, so a caller that wants a stable name for a thing
/// can hand in the thing's own number rather than keeping a second table.
pub fn memorable(seed: u128) -> String {
    let adjective = ADJECTIVES[(seed % ADJECTIVES.len() as u128) as usize];
    let noun = NOUNS[((seed / ADJECTIVES.len() as u128) % NOUNS.len() as u128) as usize];
    let tail = (seed >> 64) as u16 ^ (seed as u16);
    format!("{adjective}-{noun}-{tail:04x}")
}

/// One fresh name, for one typed command.
pub fn fresh_command() -> String {
    let token = crate::token();
    let mut seed: u128 = 0;
    for byte in token.as_bytes().iter().take(16) {
        seed = seed.wrapping_mul(131).wrapping_add(u128::from(*byte));
    }
    memorable(seed)
}

/// Whether this is a command's name rather than a worker's. Two words and four hexadecimal
/// digits is a command; anything else is not, and the two never collide.
pub fn is_command(text: &str) -> bool {
    let mut parts = text.split('-');
    let (Some(adjective), Some(noun), Some(tail), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    !adjective.is_empty()
        && !noun.is_empty()
        && adjective.chars().all(|c| c.is_ascii_lowercase())
        && noun.chars().all(|c| c.is_ascii_lowercase())
        && tail.len() == 4
        && tail.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_command_name_is_readable_aloud_and_never_looks_like_a_worker() {
        for seed in [0u128, 1, 47, 48, 2_303, 2_304, u128::MAX, 918_273_645] {
            let name = memorable(seed);
            assert!(is_command(&name), "{name}");
            assert_eq!(name, memorable(seed), "the same number must give the same name");
            assert!(!name.contains("--") && !name.ends_with('-'));
        }
        // A Swarm Mining worker is two words; a command is two words and four digits.
        assert!(!is_command("keen-heron"));
        assert!(!is_command("keen"));
        assert!(!is_command("keen-heron-3f1a-extra"));
        assert!(!is_command("keen-heron-3F1A"));
        assert!(!is_command("keen-heron-3f1"));
    }

    #[test]
    fn fresh_names_differ_and_stay_in_shape() {
        let names: std::collections::BTreeSet<String> = (0..64).map(|_| fresh_command()).collect();
        assert!(names.len() > 60, "fresh command names repeat far too often");
        for name in &names {
            assert!(is_command(name), "{name}");
        }
    }
}
