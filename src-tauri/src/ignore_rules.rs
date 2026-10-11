//! `.yougoriignore`: gitignore-style rules that decide which files a copy into an environment skips.
//! Supported: `#` comments, blank lines, `!` negation, trailing `/` for folders only, leading `/` or an
//! inner `/` to anchor at the copied folder, `*`, `?`, `[a-z]` classes and `**` across folders.
//! The last matching rule wins, as in Git. A skipped folder is never entered.

pub const FILE_NAME: &str = ".yougoriignore";

struct Rule {
    negate: bool,
    folder_only: bool,
    anchored: bool,
    segments: Vec<String>,
}

pub struct Rules(Vec<Rule>);

impl Rules {
    pub fn parse(text: &str) -> Self {
        let mut rules = Vec::new();
        for line in text.lines().take(10_000) {
            let line = line.trim_end_matches(['\r', ' ', '\t']);
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (negate, line) = match line.strip_prefix('!') {
                Some(rest) => (true, rest),
                None => (false, line),
            };
            let line = line.strip_prefix('\\').unwrap_or(line);
            let (folder_only, line) = match line.strip_suffix('/') {
                Some(rest) => (true, rest),
                None => (false, line),
            };
            let anchored = line.starts_with('/') || line.trim_start_matches('/').contains('/');
            let segments = line
                .trim_start_matches('/')
                .split('/')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect::<Vec<_>>();
            if !segments.is_empty() && line.len() <= 4096 {
                rules.push(Rule {
                    negate,
                    folder_only,
                    anchored,
                    segments,
                });
            }
        }
        Rules(rules)
    }

    /// `path` is relative to the copied folder, using `/` separators.
    pub fn ignored(&self, path: &str, folder: bool) -> bool {
        let parts = path
            .split('/')
            .filter(|s| !s.is_empty())
            .collect::<Vec<_>>();
        let mut ignored = false;
        for rule in &self.0 {
            if rule.folder_only && !folder {
                continue;
            }
            let matched = if rule.anchored {
                segments_match(&rule.segments, &parts)
            } else {
                // A bare name matches that name at any depth.
                parts
                    .last()
                    .is_some_and(|name| rule.segments.len() == 1 && glob(&rule.segments[0], name))
            };
            if matched {
                ignored = !rule.negate;
            }
        }
        ignored
    }
}

/// Whether the whole `path` matches `pattern`, where `**` spans zero or more folders.
/// Dynamic programming from the last pattern segment keeps this to one pass per
/// segment; trying every `**` split recursively is exponential for patterns such as
/// `a/**/**/**/b`.
fn segments_match(pattern: &[String], path: &[&str]) -> bool {
    // matches[j]: the remaining pattern matches path[j..].
    let mut matches = vec![false; path.len() + 1];
    matches[path.len()] = true;
    for segment in pattern.iter().rev() {
        let mut current = vec![false; path.len() + 1];
        if segment == "**" {
            let mut any = false;
            for j in (0..=path.len()).rev() {
                any |= matches[j];
                current[j] = any;
            }
        } else {
            for j in 0..path.len() {
                current[j] = matches[j + 1] && glob(segment, path[j]);
            }
        }
        matches = current;
    }
    matches[0]
}

/// Wildcard match of one path segment: `*`, `?` and `[...]` (with ranges and `!`/`^` negation).
fn glob(pattern: &str, name: &str) -> bool {
    let (p, n) = (
        pattern.chars().collect::<Vec<_>>(),
        name.chars().collect::<Vec<_>>(),
    );
    let (mut pi, mut ni) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while ni < n.len() {
        if pi < p.len() && p[pi] == '*' {
            star = Some((pi, ni));
            pi += 1;
            continue;
        }
        if pi < p.len() {
            if let Some(next) = single(&p, pi, n[ni]) {
                pi = next;
                ni += 1;
                continue;
            }
        }
        match star {
            Some((star_p, star_n)) => {
                pi = star_p + 1;
                ni = star_n + 1;
                star = Some((star_p, star_n + 1));
            }
            None => return false,
        }
    }
    p[pi..].iter().all(|c| *c == '*')
}

/// Matches one character at `pi`; returns the pattern index after it.
fn single(p: &[char], pi: usize, c: char) -> Option<usize> {
    match p[pi] {
        '?' => Some(pi + 1),
        '[' => {
            let end = p[pi + 1..]
                .iter()
                .position(|x| *x == ']')
                .map(|e| pi + 1 + e)?;
            let mut class = &p[pi + 1..end];
            let negate = matches!(class.first(), Some('!' | '^'));
            if negate {
                class = &class[1..];
            }
            let mut hit = false;
            let mut i = 0;
            while i < class.len() {
                if i + 2 < class.len() && class[i + 1] == '-' {
                    hit |= class[i] <= c && c <= class[i + 2];
                    i += 3;
                } else {
                    hit |= class[i] == c;
                    i += 1;
                }
            }
            (hit != negate).then_some(end + 1)
        }
        '\\' if pi + 1 < p.len() => (p[pi + 1] == c).then_some(pi + 2),
        literal => (literal == c).then_some(pi + 1),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn gitignore_style_rules() {
        let rules = Rules::parse("# comment\n\nnode_modules/\n*.log\n!keep.log\n/build\ndocs/**/*.pdf\n.env\n.env.*\n*.pe[mM]\nsecret?.txt\n");
        assert!(rules.ignored("node_modules", true));
        assert!(rules.ignored("web/node_modules", true));
        assert!(!rules.ignored("node_modules", false), "folder-only rule");
        assert!(rules.ignored("logs/app.log", false));
        assert!(
            !rules.ignored("logs/keep.log", false),
            "negation wins when later"
        );
        assert!(rules.ignored("build", true));
        assert!(!rules.ignored("src/build", true), "anchored to the top");
        assert!(rules.ignored("docs/a/b/c.pdf", false));
        assert!(
            rules.ignored("docs/c.pdf", false),
            "** matches zero folders"
        );
        assert!(!rules.ignored("other/c.pdf", false));
        assert!(rules.ignored(".env", false));
        assert!(rules.ignored("api/.env.local", false));
        assert!(rules.ignored("cert.pem", false) && rules.ignored("cert.peM", false));
        assert!(rules.ignored("secret1.txt", false) && !rules.ignored("secret12.txt", false));
        assert!(!rules.ignored("src/main.rs", false));
    }
    #[test]
    fn repeated_double_star_rules_stay_fast() {
        let pattern = format!("a/{}b", "**/".repeat(40));
        let rules = Rules::parse(&pattern);
        let deep = vec!["a"; 64].join("/");
        let started = std::time::Instant::now();
        assert!(!rules.ignored(&deep, false));
        assert!(rules.ignored(&format!("{deep}/b"), false));
        assert!(rules.ignored("a/b", false), "** still matches zero folders");
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
        let rules = Rules::parse("src/**/generated/**\n/**/*.tmp\n");
        assert!(rules.ignored("src/generated/x.rs", false) && rules.ignored("src/a/b/generated/c/d", false));
        assert!(!rules.ignored("src/a/generate/x.rs", false));
        assert!(rules.ignored("x/y/z.tmp", false) && rules.ignored("z.tmp", false));
    }
    #[test]
    fn wildcards() {
        assert!(glob("*", "anything") && glob("a*c", "abbbc") && glob("*.tar.gz", "x.tar.gz"));
        assert!(!glob("a*c", "abcd") && !glob("?", ""));
        assert!(glob("[!a]x", "bx") && !glob("[!a]x", "ax"));
        assert!(glob("[0-9]*", "2024.log") && !glob("[0-9]*", "x.log"));
    }
}
