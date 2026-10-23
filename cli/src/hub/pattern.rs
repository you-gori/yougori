//! The `pattern` of a text question: the everyday part of JavaScript regular expressions, so a
//! pattern behaves the same on the Hub page and in the CLI. Anchors, classes, groups, alternation
//! and quantifiers are understood; lookaround, back-references and flags are refused when the
//! template is checked, never silently ignored. Matching is bounded, so no answer can hang a run.
use std::cell::Cell;

#[derive(Debug)]
enum Node {
    Empty,
    Char(char),
    Any,
    Class(Class),
    Start,
    End,
    Concat(Vec<Node>),
    Alt(Vec<Node>),
    Repeat(Box<Node>, u32, Option<u32>),
}

#[derive(Debug)]
struct Class {
    negated: bool,
    items: Vec<Item>,
}

#[derive(Debug)]
enum Item {
    Range(char, char),
    /// `\d`, `\w`, `\s` (true) or `\D`, `\W`, `\S` (false).
    Digit(bool),
    Word(bool),
    Space(bool),
}

fn space(c: char) -> bool {
    c.is_whitespace() || c == '\u{feff}'
}

impl Item {
    fn matches(&self, c: char) -> bool {
        match self {
            Item::Range(low, high) => *low <= c && c <= *high,
            Item::Digit(yes) => c.is_ascii_digit() == *yes,
            Item::Word(yes) => (c.is_ascii_alphanumeric() || c == '_') == *yes,
            Item::Space(yes) => space(c) == *yes,
        }
    }
}

impl Class {
    fn matches(&self, c: char) -> bool {
        self.items.iter().any(|item| item.matches(c)) != self.negated
    }
}

/// A checked pattern, ready to test answers.
#[derive(Debug)]
pub struct Pattern(Node);

const MAX_LENGTH: usize = 500;
const MAX_DEPTH: usize = 20;
const MAX_REPEAT: u32 = 1000;
const STEPS: u32 = 1_000_000;

struct Parser<'a> {
    text: &'a [char],
    at: usize,
    depth: usize,
}

fn unsupported(what: &str) -> String {
    format!("The pattern uses {what}, which Yougori patterns do not support. Use anchors (^ $), classes ([a-z] \\d \\w \\s), groups, | and quantifiers (* + ? {{m,n}}).")
}

impl Parser<'_> {
    fn peek(&self) -> Option<char> {
        self.text.get(self.at).copied()
    }
    fn next(&mut self) -> Option<char> {
        let c = self.peek();
        self.at += c.is_some() as usize;
        c
    }
    fn alternation(&mut self) -> Result<Node, String> {
        let mut options = vec![self.sequence()?];
        while self.peek() == Some('|') {
            self.at += 1;
            options.push(self.sequence()?);
        }
        Ok(if options.len() == 1 { options.pop().unwrap() } else { Node::Alt(options) })
    }
    fn sequence(&mut self) -> Result<Node, String> {
        let mut nodes = Vec::new();
        while let Some(c) = self.peek() {
            if c == '|' || c == ')' {
                break;
            }
            let atom = self.atom()?;
            nodes.push(self.quantified(atom)?);
        }
        Ok(match nodes.len() {
            0 => Node::Empty,
            1 => nodes.pop().unwrap(),
            _ => Node::Concat(nodes),
        })
    }
    fn atom(&mut self) -> Result<Node, String> {
        if self.counted().is_some() {
            return Err("The pattern has {…} with nothing before it to repeat.".into());
        }
        let c = self.next().ok_or("The pattern ended early.")?;
        Ok(match c {
            '(' => {
                if self.peek() == Some('?') {
                    self.at += 1;
                    match self.next() {
                        Some(':') => {}
                        Some('=' | '!') => return Err(unsupported("lookahead")),
                        Some('<') => return Err(unsupported("lookbehind or named groups")),
                        _ => return Err(unsupported("a group option")),
                    }
                }
                self.depth += 1;
                if self.depth > MAX_DEPTH {
                    return Err("The pattern nests groups too deeply.".into());
                }
                let inner = self.alternation()?;
                self.depth -= 1;
                if self.next() != Some(')') {
                    return Err("The pattern has a ( without its ).".into());
                }
                inner
            }
            ')' => return Err("The pattern has a ) without its (.".into()),
            '[' => Node::Class(self.class()?),
            '.' => Node::Any,
            '^' => Node::Start,
            '$' => Node::End,
            '\\' => self.escape(false)?,
            '*' | '+' | '?' => return Err(format!("The pattern has {c} with nothing before it to repeat.")),
            other => Node::Char(other),
        })
    }
    /// A `{m}`, `{m,}` or `{m,n}` at the current place and its length, without moving past it.
    /// Anything else that starts with `{` is plain text, as JavaScript reads it.
    fn counted(&self) -> Option<(u32, Option<u32>, usize)> {
        if self.peek() != Some('{') {
            return None;
        }
        let rest: String = self.text[self.at + 1..].iter().take(24).collect();
        let (body, _) = rest.split_once('}')?;
        if body.is_empty() || !body.bytes().all(|b| b.is_ascii_digit() || b == b',') || body.matches(',').count() > 1 {
            return None;
        }
        let (min, max) = match body.split_once(',') {
            Some((min, "")) => (min.parse().ok()?, None),
            Some((min, max)) => (min.parse().ok()?, Some(max.parse().ok()?)),
            None => {
                let n = body.parse().ok()?;
                (n, Some(n))
            }
        };
        Some((min, max, body.len() + 2))
    }
    fn quantified(&mut self, atom: Node) -> Result<Node, String> {
        let (min, max, length) = match self.peek() {
            Some('*') => (0, None, 1),
            Some('+') => (1, None, 1),
            Some('?') => (0, Some(1), 1),
            Some('{') => match self.counted() {
                Some(found) => found,
                None => return Ok(atom),
            },
            _ => return Ok(atom),
        };
        self.at += length;
        if max.is_some_and(|max| max < min) {
            return Err("The pattern has a {m,n} with n smaller than m.".into());
        }
        if min > MAX_REPEAT || max.is_some_and(|max| max > MAX_REPEAT) {
            return Err(format!("The pattern repeats something more than {MAX_REPEAT} times."));
        }
        if matches!(atom, Node::Start | Node::End) {
            return Err("The pattern repeats ^ or $.".into());
        }
        // A lazy quantifier finds the same answers when the question is only whether one matches.
        if self.peek() == Some('?') {
            self.at += 1;
        }
        if matches!(self.peek(), Some('*' | '+')) || self.counted().is_some() {
            return Err("The pattern repeats a repetition; put it in a group instead.".into());
        }
        Ok(Node::Repeat(Box::new(atom), min, max))
    }
    fn escape(&mut self, in_class: bool) -> Result<Node, String> {
        let c = self.next().ok_or("The pattern ends with a \\.")?;
        let class = |item| Node::Class(Class { negated: false, items: vec![item] });
        Ok(match c {
            'd' => class(Item::Digit(true)),
            'D' => class(Item::Digit(false)),
            'w' => class(Item::Word(true)),
            'W' => class(Item::Word(false)),
            's' => class(Item::Space(true)),
            'S' => class(Item::Space(false)),
            'n' => Node::Char('\n'),
            't' => Node::Char('\t'),
            'r' => Node::Char('\r'),
            'f' => Node::Char('\u{c}'),
            'v' => Node::Char('\u{b}'),
            '0' if !self.peek().is_some_and(|c| c.is_ascii_digit()) => Node::Char('\0'),
            'b' | 'B' if !in_class => return Err(unsupported("word boundaries (\\b)")),
            '1'..='9' => return Err(unsupported("back-references")),
            c if c.is_ascii_alphanumeric() => return Err(unsupported(&format!("\\{c}"))),
            other => Node::Char(other),
        })
    }
    fn class(&mut self) -> Result<Class, String> {
        let negated = self.peek() == Some('^');
        self.at += negated as usize;
        let mut items = Vec::new();
        loop {
            let c = self.next().ok_or("The pattern has a [ without its ].")?;
            if c == ']' {
                break;
            }
            let low = if c == '\\' {
                match self.escape(true)? {
                    Node::Char(c) => c,
                    Node::Class(mut class) => {
                        items.append(&mut class.items);
                        continue;
                    }
                    _ => unreachable!("escapes are characters or classes"),
                }
            } else {
                c
            };
            if self.peek() == Some('-') && self.text.get(self.at + 1).is_some_and(|c| *c != ']') {
                self.at += 1;
                let c = self.next().ok_or("The pattern has a [ without its ].")?;
                let high = if c == '\\' {
                    match self.escape(true)? {
                        Node::Char(c) => c,
                        _ => return Err("The pattern has a range that ends in a class such as \\d.".into()),
                    }
                } else {
                    c
                };
                if high < low {
                    return Err(format!("The pattern has the range {low}-{high}, which runs backwards."));
                }
                items.push(Item::Range(low, high));
            } else {
                items.push(Item::Range(low, low));
            }
        }
        Ok(Class { negated, items })
    }
}

impl Pattern {
    pub fn parse(text: &str) -> Result<Pattern, String> {
        if text.chars().count() > MAX_LENGTH {
            return Err(format!("The pattern is longer than {MAX_LENGTH} characters."));
        }
        let chars: Vec<char> = text.chars().collect();
        let mut parser = Parser { text: &chars, at: 0, depth: 0 };
        let node = parser.alternation()?;
        if parser.at != chars.len() {
            return Err("The pattern has a ) without its (.".into());
        }
        Ok(Pattern(node))
    }

    /// Whether the pattern is found in `input`, as JavaScript's `test` answers; an error when
    /// the answer is too costly to decide.
    pub fn matches(&self, input: &str) -> Result<bool, String> {
        let chars: Vec<char> = input.chars().collect();
        let matcher = Matcher { input: &chars, steps: Cell::new(STEPS) };
        for start in 0..=chars.len() {
            if matcher.node(&self.0, start, &mut |_| true) {
                return Ok(true);
            }
            if matcher.steps.get() == 0 {
                return Err("This answer is too long or too complex to check against the question's pattern.".into());
            }
        }
        Ok(false)
    }
}

struct Matcher<'a> {
    input: &'a [char],
    steps: Cell<u32>,
}

impl Matcher<'_> {
    fn tick(&self) -> bool {
        let left = self.steps.get();
        self.steps.set(left.saturating_sub(1));
        left > 0
    }
    fn node(&self, node: &Node, at: usize, next: &mut dyn FnMut(usize) -> bool) -> bool {
        if !self.tick() {
            return false;
        }
        let here = self.input.get(at).copied();
        match node {
            Node::Empty => next(at),
            Node::Char(c) => here == Some(*c) && next(at + 1),
            Node::Any => here.is_some_and(|c| !matches!(c, '\n' | '\r' | '\u{2028}' | '\u{2029}')) && next(at + 1),
            Node::Class(class) => here.is_some_and(|c| class.matches(c)) && next(at + 1),
            Node::Start => at == 0 && next(at),
            Node::End => at == self.input.len() && next(at),
            Node::Concat(nodes) => self.sequence(nodes, at, next),
            Node::Alt(options) => options.iter().any(|option| self.node(option, at, next)),
            Node::Repeat(inner, min, max) => self.repeat(inner, *min, *max, 0, at, next),
        }
    }
    fn sequence(&self, nodes: &[Node], at: usize, next: &mut dyn FnMut(usize) -> bool) -> bool {
        match nodes.split_first() {
            None => next(at),
            Some((first, rest)) => self.node(first, at, &mut |after| self.sequence(rest, after, next)),
        }
    }
    /// Greedy: one more first, then stopping here. A repetition that matched nothing stops, so
    /// `(a*)*` cannot loop.
    fn repeat(&self, inner: &Node, min: u32, max: Option<u32>, count: u32, at: usize, next: &mut dyn FnMut(usize) -> bool) -> bool {
        if max.is_none_or(|max| count < max)
            && self.node(inner, at, &mut |after| (after != at || count < min) && self.repeat(inner, min, max, count + 1, after, next))
        {
            return true;
        }
        count >= min && next(at)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn test(pattern: &str, input: &str) -> bool {
        Pattern::parse(pattern).unwrap().matches(input).unwrap()
    }

    #[test]
    fn everyday_patterns_match_as_in_javascript() {
        let email = "^[^@\\s]+@[^@\\s]+$";
        assert!(test(email, "admin@example.com"));
        for bad in ["admin example.com", "a b@example.com", "@example.com", "admin@", "a@b@c"] {
            assert!(!test(email, bad), "{bad}");
        }
        assert!(test("^\\d{3}-\\d{4}$", "555-1234"));
        assert!(!test("^\\d{3}-\\d{4}$", "5555-1234"));
        assert!(test("^(cat|dog)s?$", "dogs") && test("^(cat|dog)s?$", "cat") && !test("^(cat|dog)s?$", "cow"));
        assert!(test("colou?r", "my colour is"), "unanchored patterns search, like RegExp.test");
        assert!(test("^[a-z][a-z0-9-]{1,62}$", "my-site") && !test("^[a-z][a-z0-9-]{1,62}$", "My-site"));
        assert!(test("^\\w+\\.\\w+$", "file.txt") && !test("^\\w+\\.\\w+$", "filetxt"));
        assert!(test("^a{2,}$", "aaaa") && !test("^a{2,}$", "a"));
        assert!(test("^[^]$", "^"), "[^] is any one character");
        assert!(test("x{,2}", "x{,2}"), "an incomplete count is literal text");
        assert!(test("^[-a]+$", "a-a") && test("^[a-]+$", "-"));
        assert!(test("^(?:ab)+$", "abab") && !test("^(?:ab)+$", "aba"));
        assert!(test("^.+?$", "lazy"));
    }

    #[test]
    fn unsupported_syntax_is_refused_with_its_name() {
        for (pattern, said) in [
            ("(?=x)", "lookahead"),
            ("(?<name>x)", "lookbehind or named groups"),
            ("\\bword", "word boundaries"),
            ("(a)\\1", "back-references"),
            ("\\p{L}", "\\p"),
            ("(abc", "without its )"),
            ("abc)", "without its ("),
            ("[abc", "without its ]"),
            ("*a", "nothing before it"),
            ("a{3,1}", "smaller than m"),
            ("a**", "repeats a repetition"),
            ("[z-a]", "runs backwards"),
        ] {
            let error = Pattern::parse(pattern).unwrap_err();
            assert!(error.contains(said), "{pattern}: {error}");
        }
        assert!(Pattern::parse(&"a".repeat(501)).is_err());
    }

    #[test]
    fn costly_answers_are_bounded() {
        let pattern = Pattern::parse("^(a+)+$").unwrap();
        let answer = format!("{}b", "a".repeat(40));
        let started = std::time::Instant::now();
        let outcome = pattern.matches(&answer);
        assert!(outcome.is_err() || outcome == Ok(false));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
        assert_eq!(Pattern::parse("^(a*)*$").unwrap().matches("aaa"), Ok(true), "empty repetitions stop");
    }
}
