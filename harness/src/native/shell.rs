//! Just enough shell to judge a command line: its simple commands (split at `;`, `&&`, `||`,
//! `|`, `&` and newlines), their words with quotes removed, whether one writes to a file, and
//! whether anything is hidden from that reading (command substitution, here-documents, and the
//! expansions that make bash evaluate text as code).

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Simple {
    /// The command as written.
    pub text: String,
    /// Its words, quotes and escapes removed (redirections left out).
    pub words: Vec<String>,
    /// The same words as permission patterns see them: what was quoted keeps its spaces and
    /// special characters escaped (`"old files"` is `old\ files`, one word, never two), what the
    /// shell itself reads (globs, `$`, assignments) stays as written.
    pub forms: Vec<String>,
    /// It sends output into a file (`>`, `>>`, `&>`, `>&file` to anything but /dev/null).
    pub writes: bool,
}

impl Simple {
    /// How many words at the start are `NAME=value` assignments.
    fn assignments(&self) -> usize {
        self.forms.iter().position(|w| !is_assignment(w)).unwrap_or(self.forms.len())
    }

    /// The words without leading `NAME=value` assignments.
    pub fn command_words(&self) -> &[String] {
        &self.words[self.assignments().min(self.words.len())..]
    }

    /// The words joined by single spaces, as `forms`: what permission patterns are matched against.
    pub fn normalized(&self) -> String {
        if self.forms.is_empty() {
            self.text.clone()
        } else {
            self.forms.join(" ")
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub commands: Vec<Simple>,
    /// Command or process substitution, backticks, a here-document, an unclosed quote, or an
    /// expansion that evaluates text (`$[...]`, `${x[...]}`, `${x@P}`, `${!x}`, `${x:n}`): the
    /// words do not tell everything the line runs.
    pub opaque: bool,
}

fn is_assignment(form: &str) -> bool {
    match form.split_once('=') {
        Some((name, _)) => {
            !name.is_empty()
                && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        None => false,
    }
}

/// Characters the shell gives a meaning to: quoted, they are escaped in a word's form.
fn special(c: char) -> bool {
    c.is_whitespace() || "*?[]$`'\"\\;&|<>(){}~#!=".contains(c)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Redirect {
    Write,
    Read,
    /// After `>&`: a descriptor (`2`, `-`) or, for any other word, a file both outputs go into.
    Copy,
}

struct Lexer<'a> {
    source: &'a str,
    out: Parsed,
    start: usize,
    words: Vec<String>,
    forms: Vec<String>,
    word: String,
    form: String,
    has_word: bool,
    writes: bool,
    redirect: Option<Redirect>,
}

impl<'a> Lexer<'a> {
    /// A character as the shell reads it.
    fn push(&mut self, c: char) {
        self.word.push(c);
        self.form.push(c);
        self.has_word = true;
    }

    /// A character quoted or escaped: only text.
    fn push_quoted(&mut self, c: char) {
        self.word.push(c);
        if special(c) {
            self.form.push('\\');
        }
        self.form.push(c);
        self.has_word = true;
    }

    fn clear_word(&mut self) {
        self.word.clear();
        self.form.clear();
        self.has_word = false;
    }

    fn end_word(&mut self) {
        if !self.has_word {
            return;
        }
        let word = std::mem::take(&mut self.word);
        let mut form = std::mem::take(&mut self.form);
        self.has_word = false;
        match self.redirect.take() {
            Some(Redirect::Write) => {
                if word != "/dev/null" {
                    self.writes = true;
                }
            }
            Some(Redirect::Copy) => {
                let digits = word.strip_suffix('-').unwrap_or(&word);
                let descriptor = word == "-" || (!digits.is_empty() && digits.chars().all(|d| d.is_ascii_digit()));
                if !descriptor && word != "/dev/null" {
                    self.writes = true;
                }
            }
            Some(Redirect::Read) => {}
            None => {
                if word != "{" && word != "}" {
                    if form.is_empty() {
                        // An empty quoted word is still an argument.
                        form = "''".into();
                    }
                    self.words.push(word);
                    self.forms.push(form);
                }
            }
        }
    }

    fn end_command(&mut self, at: usize) {
        self.end_word();
        if matches!(self.redirect.take(), Some(Redirect::Write | Redirect::Copy)) {
            // `cmd >` with nothing after it still means a write was meant.
            self.writes = true;
        }
        let text = self.source[self.start..at].trim().trim_matches(|c| c == '(' || c == ')').trim().to_owned();
        if !self.words.is_empty() || self.writes {
            self.out.commands.push(Simple {
                text,
                words: std::mem::take(&mut self.words),
                forms: std::mem::take(&mut self.forms),
                writes: self.writes,
            });
        }
        self.words.clear();
        self.forms.clear();
        self.writes = false;
    }
}

/// Whether the `${` before `start` opens an expansion that makes bash evaluate text: a subscript
/// (`${a[$i]}`), a substring's offsets (`${x:n}`), a transformation (`${x@P}` runs a value as a
/// prompt), an indirection (`${!x}`), or anything this reading does not know.
fn brace_evaluates(chars: &[(usize, char)], start: usize) -> bool {
    let at = |k: usize| chars.get(k).map(|(_, c)| *c);
    let mut j = start;
    match at(j) {
        Some('!') => return true,
        Some('#') if at(j + 1) == Some('}') => return false,
        Some('#') => j += 1,
        _ => {}
    }
    let name = j;
    while at(j).is_some_and(|c| c.is_ascii_alphanumeric() || c == '_') {
        j += 1;
    }
    if j == name {
        match at(j) {
            Some(c) if "@*#?-$!".contains(c) => j += 1,
            _ => return true,
        }
    }
    match at(j) {
        Some('}') => false,
        Some(':') => !matches!(at(j + 1), Some('-' | '=' | '?' | '+')),
        Some('-' | '=' | '?' | '+' | '#' | '%' | '/' | '^' | ',') => false,
        _ => true,
    }
}

pub fn parse(command: &str) -> Parsed {
    let chars: Vec<(usize, char)> = command.char_indices().collect();
    let mut lx = Lexer {
        source: command,
        out: Parsed::default(),
        start: 0,
        words: Vec::new(),
        forms: Vec::new(),
        word: String::new(),
        form: String::new(),
        has_word: false,
        writes: false,
        redirect: None,
    };
    let at = |i: usize| chars.get(i).map(|(_, c)| *c);
    let offset = |i: usize| chars.get(i).map(|(o, _)| *o).unwrap_or(command.len());
    // `$(`, `$[` and the `${...}` forms that evaluate text hide what the line runs.
    let dollar_hides = |i: usize| match at(i + 1) {
        Some('(' | '[') => true,
        Some('{') => brace_evaluates(&chars, i + 2),
        _ => false,
    };
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i].1;
        match c {
            ' ' | '\t' => lx.end_word(),
            '\n' | ';' => {
                lx.end_command(offset(i));
                lx.start = offset(i + 1);
            }
            '&' if at(i + 1) == Some('&') => {
                lx.end_command(offset(i));
                i += 1;
                lx.start = offset(i + 1);
            }
            '&' if at(i + 1) == Some('>') => {
                lx.end_word();
                i += 1;
                if at(i + 1) == Some('>') {
                    i += 1;
                }
                lx.redirect = Some(Redirect::Write);
            }
            '&' => {
                lx.end_command(offset(i));
                lx.start = offset(i + 1);
            }
            '|' => {
                lx.end_command(offset(i));
                if matches!(at(i + 1), Some('|') | Some('&')) {
                    i += 1;
                }
                lx.start = offset(i + 1);
            }
            '(' | ')' => {
                lx.end_command(offset(i));
                lx.start = offset(i + 1);
            }
            '>' => {
                // `2>`: the digits before are the descriptor, not a word.
                if lx.has_word && lx.word.chars().all(|d| d.is_ascii_digit()) {
                    lx.clear_word();
                } else {
                    lx.end_word();
                }
                if at(i + 1) == Some('(') {
                    // `>(cmd)`: a process substitution.
                    lx.out.opaque = true;
                }
                if at(i + 1) == Some('&') {
                    // `>&2`, `2>&1` copy a descriptor; `>&file` writes the file (as `&>file`).
                    i += 1;
                    lx.redirect = Some(Redirect::Copy);
                } else {
                    if at(i + 1) == Some('>') || at(i + 1) == Some('|') {
                        i += 1;
                    }
                    lx.redirect = Some(Redirect::Write);
                }
            }
            '<' => {
                if at(i + 1) == Some('(') || at(i + 1) == Some('<') {
                    lx.out.opaque = true;
                }
                if lx.has_word && lx.word.chars().all(|d| d.is_ascii_digit()) {
                    lx.clear_word();
                } else {
                    lx.end_word();
                }
                while matches!(at(i + 1), Some('<') | Some('&')) {
                    i += 1;
                }
                lx.redirect = Some(Redirect::Read);
            }
            '#' if !lx.has_word => {
                while i + 1 < chars.len() && chars[i + 1].1 != '\n' {
                    i += 1;
                }
            }
            '\'' => {
                lx.has_word = true;
                let mut closed = false;
                while i + 1 < chars.len() {
                    i += 1;
                    if chars[i].1 == '\'' {
                        closed = true;
                        break;
                    }
                    lx.push_quoted(chars[i].1);
                }
                if !closed {
                    lx.out.opaque = true;
                }
            }
            '"' => {
                lx.has_word = true;
                let mut closed = false;
                while i + 1 < chars.len() {
                    i += 1;
                    match chars[i].1 {
                        '"' => {
                            closed = true;
                            break;
                        }
                        '\\' if matches!(at(i + 1), Some('$') | Some('`') | Some('"') | Some('\\') | Some('\n')) => {
                            i += 1;
                            if chars[i].1 != '\n' {
                                lx.push_quoted(chars[i].1);
                            }
                        }
                        '`' => {
                            lx.out.opaque = true;
                            lx.push('`');
                        }
                        '$' => {
                            if dollar_hides(i) {
                                lx.out.opaque = true;
                            }
                            lx.push('$');
                        }
                        other => lx.push_quoted(other),
                    }
                }
                if !closed {
                    lx.out.opaque = true;
                }
            }
            '\\' => {
                if let Some(next) = at(i + 1) {
                    i += 1;
                    if next != '\n' {
                        lx.push_quoted(next);
                    }
                }
            }
            '`' => {
                lx.out.opaque = true;
                lx.push('`');
            }
            '$' => {
                if dollar_hides(i) {
                    lx.out.opaque = true;
                }
                lx.push('$');
            }
            other => lx.push(other),
        }
        i += 1;
    }
    lx.end_command(command.len());
    lx.out
}

/// Programs that only read, whatever their arguments (output redirection is judged apart).
/// Programs that only read with some of their options are judged in `simple_read_only`.
const READ_ONLY: &[&str] = &[
    "ls", "ll", "la", "dir", "pwd", "cat", "head", "tail", "more", "wc", "echo", "which", "whereis", "whoami",
    "id", "groups", "uname", "cal", "stat", "du", "df", "grep", "egrep", "fgrep", "diff", "cmp", "comm", "cut",
    "tr", "nl", "fold", "fmt", "column", "paste", "rev", "tac", "expand", "unexpand", "basename", "dirname",
    "realpath", "readlink", "true", "false", "type", "sha1sum", "sha224sum", "sha256sum", "sha384sum",
    "sha512sum", "md5sum", "b2sum", "cksum", "sum", "hexdump", "od", "strings", "nproc", "free", "uptime", "ps",
    "pgrep", "lscpu", "lsblk", "seq", "sleep", "jq", "cd", "pushd", "popd", "dirs", "locale", "arch", "getconf",
    "tty", "zcat", "bzcat", "xzcat", "base64", "numfmt", "expr", "help",
];

/// Toolchains whose `--version` only prints. Not those that first run what the project names:
/// cargo, rustc and rustup (a rust-toolchain.toml path), yarn (yarnPath), mvn (.mvn/jvm.config),
/// gradle (gradle.properties), pytest (conftest.py) and composer (plugins in vendor/).
const VERSIONED: &[&str] = &[
    "python", "python3", "node", "npm", "npx", "pnpm", "bun", "deno", "go", "java", "javac", "gcc", "g++", "cc",
    "clang", "clang++", "make", "cmake", "docker", "kubectl", "pip", "pip3", "uv", "poetry", "ruby", "gem", "php",
    "dotnet", "swift", "terraform", "ninja", "meson", "tsc", "eslint", "prettier", "black", "ruff", "mypy", "perl",
    "lua", "zig", "git",
];

/// Variables a command may be given in front of it that change nothing but how it prints.
fn inert(name: &str) -> bool {
    matches!(name, "LANG" | "LANGUAGE" | "TZ" | "NO_COLOR" | "COLUMNS" | "LINES") || name.starts_with("LC_")
}

fn program_name(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// How a program reads its options, to find the dangerous ones wherever they are written:
/// `bad` letters also inside clusters (`-uo`), `bad_long` names also abbreviated (`--outp`), as
/// getopt allows. `takes` are the letters whose value is the rest of the cluster or the next
/// argument, `optional` the ones whose value can only be attached; any other letter is a flag.
/// Leaving a letter out of `takes` only makes the check stricter.
struct Options<'a> {
    takes: &'a str,
    optional: &'a str,
    bad: &'a str,
    bad_long: &'a [&'a str],
}

impl Options<'_> {
    fn used_in(&self, args: &[&str]) -> bool {
        let mut i = 0;
        while i < args.len() {
            let arg = args[i];
            i += 1;
            if arg == "--" {
                return false;
            }
            if let Some(long) = arg.strip_prefix("--") {
                let name = long.split_once('=').map_or(long, |(name, _)| name);
                if !name.is_empty() && self.bad_long.iter().any(|bad| bad.starts_with(name)) {
                    return true;
                }
                continue;
            }
            let Some(cluster) = arg.strip_prefix('-') else { continue };
            for (at, letter) in cluster.char_indices() {
                if self.bad.contains(letter) {
                    return true;
                }
                if self.takes.contains(letter) {
                    if at + letter.len_utf8() == cluster.len() {
                        i += 1;
                    }
                    break;
                }
                if self.optional.contains(letter) {
                    break;
                }
            }
        }
        false
    }

    /// The arguments that are not options or their values.
    fn operands<'s>(&self, args: &[&'s str]) -> Vec<&'s str> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let arg = args[i];
            i += 1;
            if arg == "--" {
                out.extend_from_slice(&args[i..]);
                break;
            }
            if arg.starts_with("--") {
                continue;
            }
            match arg.strip_prefix('-').filter(|c| !c.is_empty()) {
                Some(cluster) => {
                    for (at, letter) in cluster.char_indices() {
                        if self.takes.contains(letter) {
                            if at + letter.len_utf8() == cluster.len() {
                                i += 1;
                            }
                            break;
                        }
                    }
                }
                None => out.push(arg),
            }
        }
        out
    }
}

/// Whether the whole command line only reads: every simple command is a known reader and
/// nothing writes into a file or hides a command inside another.
#[cfg(test)]
pub fn read_only(command: &str) -> bool {
    let parsed = parse(command);
    !parsed.opaque && !parsed.commands.is_empty() && parsed.commands.iter().all(simple_read_only)
}

/// Whether one simple command only reads (the line's substitutions are judged apart).
pub fn simple_read_only(simple: &Simple) -> bool {
    if simple.writes {
        return false;
    }
    // `LESSOPEN=... less`, `GIT_EXTERNAL_DIFF=... git diff`, `PATH=.:$PATH`, `LD_PRELOAD=...`:
    // a variable can make the program (or every later one) run other code.
    let assigned = simple.assignments();
    if simple.forms[..assigned].iter().any(|form| !form.split_once('=').is_some_and(|(name, _)| inert(name))) {
        return false;
    }
    let words = simple.command_words();
    let Some(first) = words.first() else { return true };
    let program = program_name(first);
    let args: Vec<&str> = words[1..].iter().map(String::as_str).collect();
    if VERSIONED.contains(&program) && matches!(args.as_slice(), ["--version"] | ["-V"] | ["version"]) {
        return true;
    }
    if READ_ONLY.contains(&program) {
        return true;
    }
    let flags = |bad: &str, bad_long: &[&str]| !Options { takes: "", optional: "", bad, bad_long }.used_in(&args);
    match program {
        // `test -v 'a[$(cmd)]'` and `printf -v 'a[$(cmd)]'` evaluate the subscript.
        "test" | "[" => !args.iter().any(|a| matches!(*a, "-v" | "-R")),
        "printf" => !args.first().is_some_and(|a| a.starts_with("-v") || (*a == "--" && args.get(1).is_some_and(|b| b.starts_with("-v")))),
        // Only `command -v NAME` and `command -V NAME`: `command rm -rf .` runs rm.
        "command" => matches!(args.first(), Some(&("-v" | "-V"))) && args.len() > 1 && args[1..].iter().all(|a| !a.starts_with('-')),
        // `uniq IN OUT` writes OUT.
        "uniq" => Options { takes: "fsw", optional: "", bad: "", bad_long: &[] }.operands(&args).len() <= 1,
        // `tree -o FILE` writes it, `-R` writes a page into every folder.
        "tree" => flags("oR", &[]),
        // `man -P CMD` runs CMD as the pager; -H and -X start a browser or viewer; -C reads a
        // configuration that can name programs.
        "man" => flags("PHXC", &["pager", "html", "gxditview", "config-file"]),
        "whatis" | "apropos" => flags("C", &["config-file"]),
        // `date -s` sets the clock.
        "date" => !Options { takes: "dfr", optional: "I", bad: "s", bad_long: &["set"] }.used_in(&args),
        // `hostname NAME` (or -F, -b) sets the name.
        "hostname" => args.iter().all(|a| a.starts_with('-')) && flags("Fb", &["file", "boot"]),
        // `file -C` compiles a magic file into a new file.
        "file" => !Options { takes: "mfFeP", optional: "", bad: "C", bad_long: &["compile"] }.used_in(&args),
        // `less -o FILE` copies its input into FILE; a lesskey file can bind commands.
        "less" => flags("oOk", &["log-file", "LOG-FILE", "lesskey-file", "lesskey-src", "lesskey-content"]),
        "sort" => !Options { takes: "kStT", optional: "", bad: "o", bad_long: &["output", "compress-program"] }.used_in(&args),
        "find" => !args.iter().any(|a| {
            matches!(*a, "-delete" | "-exec" | "-execdir" | "-ok" | "-okdir" | "-fprint" | "-fprint0" | "-fprintf" | "-fls")
        }),
        "fd" | "fdfind" => flags("xX", &["exec", "exec-batch"]),
        "rg" => !args.iter().any(|a| a.starts_with("--pre")),
        "ag" => flags("", &["pager"]),
        "sed" => sed_read_only(&args),
        "git" => git_read_only(&args),
        "npm" | "pnpm" => matches!(args.first(), Some(&("ls" | "list" | "ll" | "view" | "info" | "outdated" | "root" | "why"))),
        "pip" | "pip3" => matches!(args.first(), Some(&("list" | "show" | "freeze" | "check"))),
        "go" => match args.first() {
            Some(&("version" | "doc")) => true,
            // -toolexec and builds (-export, -compiled) run other programs.
            Some(&"list") => !args.iter().any(|a| ["toolexec", "exec", "export", "compiled"].iter().any(|bad| a.trim_start_matches('-').starts_with(bad))),
            Some(&"env") => !args.iter().any(|a| matches!(*a, "-w" | "-u")),
            _ => false,
        },
        "docker" | "podman" => matches!(args.first(), Some(&("ps" | "images" | "inspect" | "logs" | "info" | "version"))),
        // A kubeconfig names programs to run for credentials.
        "kubectl" => {
            matches!(args.first(), Some(&("get" | "describe" | "logs" | "version" | "explain"))) && !args.iter().any(|a| a.starts_with("--kubeconfig"))
        }
        _ => false,
    }
}

/// Whether a sed command line only prints: known harmless options, and a script made only of
/// commands that select, change in the output or print lines (no `e`, `w`, `r`, no script file,
/// no editing in place).
fn sed_read_only(args: &[&str]) -> bool {
    const FLAGS: &[&str] = &[
        "null-data", "zero-terminated", "quiet", "silent", "regexp-extended", "separate", "unbuffered", "posix", "debug",
        "sandbox", "binary", "follow-symlinks", "help", "version",
    ];
    let mut scripts: Vec<String> = Vec::new();
    let mut operands: Vec<&str> = Vec::new();
    let mut i = 0;
    let mut options = true;
    while i < args.len() {
        let arg = args[i];
        i += 1;
        if !options || arg == "-" || !arg.starts_with('-') {
            operands.push(arg);
            continue;
        }
        if arg == "--" {
            options = false;
            continue;
        }
        if let Some(long) = arg.strip_prefix("--") {
            let (name, value) = match long.split_once('=') {
                Some((name, value)) => (name, Some(value)),
                None => (long, None),
            };
            let known = ["expression", "file", "in-place", "line-length"].iter().chain(FLAGS);
            let mut found: Vec<&str> = known.filter(|full| full.starts_with(name)).copied().collect();
            if found.contains(&name) {
                found = vec![name];
            }
            match found.as_slice() {
                [] => return false,
                ["expression"] => match value.or_else(|| args.get(i).copied()) {
                    Some(script) => {
                        if value.is_none() {
                            i += 1;
                        }
                        scripts.push(script.to_owned());
                    }
                    None => return false,
                },
                ["line-length"] => {
                    if value.is_none() {
                        i += 1;
                    }
                }
                found if found.iter().all(|full| FLAGS.contains(full)) => {}
                // --file, --in-place, or an abbreviation that could be either.
                _ => return false,
            }
            continue;
        }
        let cluster = &arg[1..];
        for (at, letter) in cluster.char_indices() {
            match letter {
                'n' | 'r' | 'E' | 's' | 'u' | 'z' => {}
                'e' | 'l' => {
                    let rest = &cluster[at + 1..];
                    let value = if rest.is_empty() {
                        i += 1;
                        args.get(i - 1).copied()
                    } else {
                        Some(rest)
                    };
                    match (letter, value) {
                        ('e', Some(script)) => scripts.push(script.to_owned()),
                        (_, None) => return false,
                        _ => {}
                    }
                    break;
                }
                // -i edits in place, -f reads the script from a file; anything else is unknown.
                _ => return false,
            }
        }
    }
    if scripts.is_empty() {
        if operands.is_empty() {
            return false;
        }
        scripts.push(operands.remove(0).to_owned());
    }
    sed_script_prints_only(&scripts.join("\n"))
}

/// Whether a sed script is made only of commands that cannot run anything or write a file.
fn sed_script_prints_only(script: &str) -> bool {
    let chars: Vec<char> = script.chars().collect();
    let n = chars.len();
    let mut i = 0;
    let blanks = |i: &mut usize| {
        while *i < n && matches!(chars[*i], ' ' | '\t') {
            *i += 1;
        }
    };
    loop {
        while i < n && matches!(chars[i], ' ' | '\t' | '\n' | ';') {
            i += 1;
        }
        if i >= n {
            return true;
        }
        if chars[i] == '#' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        if !sed_address(&chars, &mut i, false) {
            return false;
        }
        blanks(&mut i);
        if i < n && chars[i] == ',' {
            i += 1;
            blanks(&mut i);
            if !sed_address(&chars, &mut i, true) {
                return false;
            }
            blanks(&mut i);
        }
        while i < n && chars[i] == '!' {
            i += 1;
            blanks(&mut i);
        }
        let Some(&command) = chars.get(i) else { return false };
        i += 1;
        match command {
            '{' => continue,
            '}' | 'p' | 'P' | '=' | 'd' | 'D' | 'n' | 'N' | 'g' | 'G' | 'h' | 'H' | 'x' | 'z' | 'F' => {}
            'l' | 'q' | 'Q' => {
                blanks(&mut i);
                while i < n && chars[i].is_ascii_digit() {
                    i += 1;
                }
            }
            's' => {
                let Some(&delimiter) = chars.get(i).filter(|d| !matches!(d, '\n' | '\\')) else { return false };
                i += 1;
                if !sed_until(&chars, &mut i, delimiter) || !sed_until(&chars, &mut i, delimiter) {
                    return false;
                }
                // Flags: never e (runs the result) or w (writes a file).
                while i < n && matches!(chars[i], 'g' | 'p' | 'i' | 'I' | 'm' | 'M' | '0'..='9') {
                    i += 1;
                }
            }
            'y' => {
                let Some(&delimiter) = chars.get(i).filter(|d| !matches!(d, '\n' | '\\')) else { return false };
                i += 1;
                if !sed_until(&chars, &mut i, delimiter) || !sed_until(&chars, &mut i, delimiter) {
                    return false;
                }
            }
            // e, w, W, r, R, a, i, c, labels and branches, and anything unknown.
            _ => return false,
        }
        blanks(&mut i);
        if i < n && !matches!(chars[i], ';' | '\n' | '}' | '#') {
            return false;
        }
    }
}

/// One sed address, when there is one: a line number (`3`, `1~2`), `$`, `/re/` or `\cREc` with
/// I and M after it; the second of a range may also be `+N` or `~N`. False when it is broken.
fn sed_address(chars: &[char], i: &mut usize, second: bool) -> bool {
    let digits = |i: &mut usize| {
        let from = *i;
        while chars.get(*i).is_some_and(char::is_ascii_digit) {
            *i += 1;
        }
        *i > from
    };
    match chars.get(*i) {
        Some(c) if c.is_ascii_digit() => {
            digits(i);
            if chars.get(*i) == Some(&'~') {
                *i += 1;
                return digits(i);
            }
            true
        }
        Some('+' | '~') if second => {
            *i += 1;
            digits(i)
        }
        Some('$') => {
            *i += 1;
            true
        }
        Some('/') => {
            *i += 1;
            if !sed_until(chars, i, '/') {
                return false;
            }
            while matches!(chars.get(*i), Some('I' | 'M')) {
                *i += 1;
            }
            true
        }
        Some('\\') => {
            let Some(&delimiter) = chars.get(*i + 1).filter(|d| !matches!(d, '\n' | '\\')) else { return false };
            *i += 2;
            if !sed_until(chars, i, delimiter) {
                return false;
            }
            while matches!(chars.get(*i), Some('I' | 'M')) {
                *i += 1;
            }
            true
        }
        _ => !second,
    }
}

/// Moves past the text up to an unescaped `delimiter` and the delimiter itself, as GNU sed reads
/// it (a backslash takes the character after it, a bare line break ends it unfinished).
fn sed_until(chars: &[char], i: &mut usize, delimiter: char) -> bool {
    while let Some(&c) = chars.get(*i) {
        *i += 1;
        if c == '\\' {
            if chars.get(*i).is_none() {
                return false;
            }
            *i += 1;
        } else if c == delimiter {
            return true;
        } else if c == '\n' {
            return false;
        }
    }
    false
}

fn git_read_only(args: &[&str]) -> bool {
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') {
        match args[i] {
            "--no-pager" | "--no-optional-locks" | "-P" | "--no-replace-objects" | "--literal-pathspecs" => i += 1,
            "-C" => i += 2,
            "--version" | "--help" => return true,
            // -c, --config-env, --git-dir, --work-tree, --exec-path=, --namespace and the rest
            // change what git runs or where its settings come from.
            _ => return false,
        }
    }
    let Some(sub) = args.get(i) else { return true };
    let rest = &args[(i + 1).min(args.len())..];
    // A long option by its name, abbreviated or followed by more (`--out`, `--output-indicator-new`).
    let long = |arg: &str, option: &str| {
        arg.strip_prefix("--")
            .map(|a| a.split_once('=').map_or(a, |(name, _)| name))
            .is_some_and(|name| !name.is_empty() && (option.starts_with(name) || name.starts_with(option)))
    };
    // Output into a file (--output), an external diff program, text conversion programs.
    if rest.iter().any(|a| long(a, "output") || long(a, "ext-diff") || long(a, "textconv")) {
        return false;
    }
    match *sub {
        "status" | "diff" | "log" | "show" | "blame" | "annotate" | "rev-parse" | "ls-files" | "ls-tree" | "describe"
        | "shortlog" | "merge-base" | "name-rev" | "whatchanged" | "rev-list" | "count-objects" | "for-each-ref"
        | "show-ref" | "check-ignore" | "version" | "var" | "cherry" => true,
        // -O / --open-files-in-pager runs the pager it names.
        "grep" => !Options { takes: "", optional: "", bad: "O", bad_long: &["open-files-in-pager"] }.used_in(rest),
        // --upload-pack / -u runs the program it names.
        "ls-remote" => !Options { takes: "", optional: "", bad: "u", bad_long: &["upload-pack"] }.used_in(rest),
        "cat-file" => !rest.iter().any(|a| long(a, "filters")),
        "help" => !Options { takes: "", optional: "", bad: "w", bad_long: &["web"] }.used_in(rest),
        "branch" => rest.iter().all(|a| {
            matches!(
                *a,
                "-a" | "--all" | "-r" | "--remotes" | "-v" | "-vv" | "--verbose" | "--list" | "-l" | "--show-current"
                    | "--no-color" | "--color"
            )
        }),
        "tag" => rest.is_empty() || matches!(rest.first(), Some(&("-l" | "--list"))),
        "remote" => rest.is_empty() || matches!(rest.first(), Some(&("-v" | "show" | "get-url"))),
        "config" => {
            rest.iter().any(|a| matches!(*a, "--get" | "--get-all" | "--list" | "-l" | "--get-regexp"))
                && !rest.iter().any(|a| {
                    matches!(*a, "--add" | "--unset" | "--unset-all" | "--replace-all" | "--edit" | "-e" | "--rename-section" | "--remove-section")
                })
        }
        "stash" => matches!(rest.first(), Some(&("list" | "show"))),
        "worktree" => matches!(rest.first(), Some(&"list")),
        "reflog" => rest.is_empty() || matches!(rest.first(), Some(&"show")),
        _ => false,
    }
}

/// Programs an "always" answer allows only as the exact command, never by their first words.
const EXACT_ONLY: &[&str] = &[
    "rm", "rmdir", "mv", "dd", "shred", "truncate", "unlink", "chmod", "chown", "chgrp", "sudo", "su", "doas",
    "kill", "pkill", "killall", "reboot", "shutdown", "poweroff", "halt", "mkfs", "fdisk", "parted", "eval", "exec",
    "source", ".", "bash", "sh", "zsh", "dash", "fish", "xargs", "crontab",
];

/// Programs whose second word picks what they do (`git status`, `cargo test`).
const SUBCOMMANDS: &[&str] = &[
    "git", "cargo", "npm", "npx", "pnpm", "yarn", "bun", "deno", "go", "docker", "podman", "kubectl", "helm", "pip",
    "pip3", "uv", "poetry", "pdm", "apt", "apt-get", "brew", "systemctl", "gh", "rustup", "dotnet", "mvn", "gradle",
    "./gradlew", "conda", "terraform", "composer", "gem", "bundle", "rake", "mix", "swift", "flutter", "dart", "nx",
    "turbo", "make", "just", "task", "hatch", "pipenv", "tox", "nox",
];

/// The pattern an "always" answer adds for this command: its first words and `*` (`git status*`),
/// or the exact command for programs that delete, move or run other code.
pub fn always_pattern(simple: &Simple) -> String {
    let start = simple.assignments().min(simple.words.len());
    let words = &simple.words[start..];
    let forms = &simple.forms[start..];
    let Some(first) = words.first() else { return escape(&simple.normalized()) };
    let program = program_name(first);
    if EXACT_ONLY.contains(&program) {
        return escape(&simple.normalized());
    }
    let second = words.get(1).map(String::as_str);
    let count = match (program, second) {
        ("npm" | "pnpm" | "yarn" | "bun", Some("run" | "exec")) => 3,
        ("python" | "python3", Some("-m")) => 3,
        ("docker" | "podman", Some("compose")) => 3,
        ("uv" | "poetry" | "pdm" | "hatch" | "pipenv", Some("run")) => 3,
        (p, Some(s)) if SUBCOMMANDS.contains(&p) && !s.starts_with('-') => 2,
        _ => 1,
    };
    let taken: Vec<&str> = forms.iter().take(count).map(String::as_str).collect();
    format!("{}*", escape(&taken.join(" ")))
}

/// A permission pattern matching `text` literally.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '*' | '?' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn texts(command: &str) -> Vec<String> {
        parse(command).commands.into_iter().map(|c| c.text).collect()
    }

    #[test]
    fn commands_split_at_operators_and_quotes_hold_them() {
        assert_eq!(texts("cd src && cargo test; echo 'a && b' | wc -l"), vec!["cd src", "cargo test", "echo 'a && b'", "wc -l"]);
        let parsed = parse("git commit -m \"fix: a; b\" || (echo failed)");
        assert_eq!(parsed.commands[0].words, vec!["git", "commit", "-m", "fix: a; b"]);
        assert_eq!(parsed.commands[1].words, vec!["echo", "failed"]);
        assert!(!parsed.opaque);
        assert!(parse("echo $(rm -rf /)").opaque);
        assert!(parse("cat <<EOF\nx\nEOF").opaque);
        assert!(parse("echo `id`").opaque);
        assert!(parse("echo 'open").opaque);
        assert!(!parse("echo \"$HOME\"").opaque);
    }

    #[test]
    fn redirections_into_files_are_writes() {
        assert!(parse("echo hi > out.txt").commands[0].writes);
        assert!(parse("echo hi >> out.txt").commands[0].writes);
        assert!(parse("make &> log").commands[0].writes);
        assert!(!parse("ls 2>&1").commands[0].writes);
        assert!(!parse("ls 2>/dev/null").commands[0].writes);
        assert!(!parse("ls >&2").commands[0].writes);
        assert_eq!(parse("ls 2>/dev/null").commands[0].words, vec!["ls"]);
        // `>&word` with a word that is no descriptor writes that file, as `&>word` does.
        for command in ["echo x >&out.txt", "echo x >& out.txt", "echo x >&2x", "echo x >&\"$F\"", "cat a >&/dev/tcp/host/80", "cat <>new"] {
            assert!(parse(command).commands[0].writes, "{command}");
        }
        for command in ["ls 2>&1", "ls >&-", "ls 2>&-", "ls 3>&2-", "ls 1>&2 2>/dev/null", "ls >&/dev/null"] {
            assert!(!parse(command).commands[0].writes, "{command}");
        }
        assert_eq!(parse("ls 2>&1 | wc -l").commands[0].words, vec!["ls"]);
    }

    #[test]
    fn read_only_commands_are_recognised() {
        for command in [
            "ls -la",
            "cat src/main.rs | head -50",
            "git status",
            "git --no-pager log --oneline -5",
            "git -C sub log --oneline",
            "git diff HEAD~1 -- src",
            "git log --no-ext-diff -p",
            "git grep -n -o pattern",
            "git ls-remote origin",
            "grep -rn 'fn main' src 2>/dev/null",
            "find . -name '*.rs' -type f",
            "rg TODO",
            "sed -n '1,20p' a.txt",
            "sed -n '$p' a.txt",
            "sed -n '/start/,/end/p' a.txt",
            "sed 's/foo/bar/g' a.txt",
            "sed -E 's/(a|b)+/x/2g;5q' a.txt",
            "sed -e '1d' -e 's|a|b|' a.txt",
            "sed -n '/x/{p;q}' a.txt",
            "sed -n '\\,re,Ip' a.txt",
            "sed 'y/abc/xyz/' a.txt",
            "sed -n '0,/re/p;10,+2p;1~3=' a.txt",
            "sed --quiet --expression='2p' a.txt",
            "python3 --version",
            "cd sub && ls",
            "LC_ALL=C wc -l a",
            "LANG=C TZ=UTC date",
            "date -Iseconds",
            "date -d 'last sunday' +%F",
            "git branch -a",
            "npm ls",
            "command -v cargo",
            "uniq -c sorted.txt",
            "uniq -f 1 sorted.txt",
            "sort -u -k 2 names.txt",
            "tree -L 2 src",
            "man git-log",
            "hostname -f",
            "file -b image.png",
            "less README.md",
            "test -f Cargo.toml",
            "[ -d src ]",
            "printf '%s\\n' a b",
            "echo \"${HOME}\" ${#PATH} ${x:-default} ${x%.rs}",
        ] {
            assert!(read_only(command), "{command} should read only");
        }
        for command in [
            "rm -rf build",
            "echo x > a.txt",
            "find . -name '*.tmp' -delete",
            "find . -exec rm {} \\;",
            "sed -i 's/a/b/' f",
            "sed -n 's/a/b/w out' f",
            "git commit -m x",
            "git push",
            "git branch new-feature",
            "cargo test",
            "npm install",
            "ls $(rm x)",
            "sort -o out in",
            "python3 script.py",
            "ls; rm a",
            "curl https://example.com",
            "",
            // Any command at all behind `command`, and programs that write by their arguments.
            "command rm -rf .",
            "command curl -s URL | command sh",
            "command -p rm x",
            "uniq README.md /home/node/.bashrc",
            "uniq -c in out",
            "tree -o out.txt",
            "tree -ao out.txt",
            "tree -R -H . src",
            "man -P 'sh -c id' ls",
            "man --pager=id ls",
            "man -Hfirefox ls",
            "man --html=x ls",
            "man -C ./man.conf ls",
            "apropos -C ./man.conf x",
            "date -s 2020-01-01",
            "date -us 2020-01-01",
            "date --set=2020-01-01",
            "date --se 2020-01-01",
            "hostname evil",
            "hostname -F name.txt",
            "file -C -m magic",
            "less -o copy.txt README.md",
            "less --log-file=copy.txt README.md",
            "sort -uo out in",
            "sort --outp=out in",
            "sort -S 1 --compress-program=./x big",
            "fd -Hx rm",
            "fd --exec rm",
            "ack needle",
            "yarn why x",
            "cargo search x",
            "cargo --list",
            "cargo --version",
            "rustc --version",
            "yarn --version",
            "mvn --version",
            "pytest --version",
            "go env -u GOFLAGS",
            "go list -toolexec ./x ./...",
            "kubectl get pods --kubeconfig=./k.yaml",
            // Assignments before a command change what it runs.
            "FOO=1 wc -l a",
            "LESSOPEN='|sh -c \"id\" %s' less README.md",
            "GIT_EXTERNAL_DIFF=./x git diff",
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=core.fsmonitor GIT_CONFIG_VALUE_0=./x git status",
            "LD_PRELOAD=./x.so ls",
            "PATH=.:$PATH",
            "PATH=.:$PATH; git status",
            // git's ways to run programs or write files.
            "git -c core.fsmonitor='sh -c id' status",
            "git -c diff.external=./x diff",
            "git --config-env=core.pager=X log",
            "git --git-dir=/tmp/x status",
            "git --work-tree=/tmp status",
            "git --exec-path=./bin status",
            "git grep -O'sh -c id' x",
            "git grep -iO x",
            "git grep --open-files-in-pager=id x",
            "git grep --open x",
            "git ls-remote --upload-pack='touch x;' .",
            "git ls-remote -u./x .",
            "git log -1 --output=/home/node/.bashrc",
            "git log --out=f",
            "git diff --ext-diff",
            "git show --textconv HEAD",
            "git cat-file --filters HEAD:a",
            "git help --web log",
            // sed scripts that run commands or write files.
            "sed -n '$e id' README.md",
            "sed 's|.*|id|e;q' README.md",
            "sed --expression='e id' f",
            "sed --exp='e id' f",
            "sed -e p -e 'w out' f",
            "sed -n '$w /home/node/.bashrc'",
            "sed -n '1,3w FILE' f",
            "sed -n 'wFILE' f",
            "sed -f script.sed f",
            "sed --file=script.sed f",
            "sed -s -i 's/a/b/' f",
            "sed -n '1r /etc/passwd' f",
            "sed '1a text' f",
            "sed -n",
            "sed 's/a/b' f",
            // Commands hidden in quotes or variables that bash evaluates.
            "test -v 'a[$(id)]'",
            "[ -v 'a[$(id)]' ]",
            "x='a[$(id)]'; echo $[x]",
            "echo $[1+1]",
            "x='$(id)'; echo \"${x@P}\"",
            "echo ${x@P}",
            "echo ${!x}",
            "echo \"${a[$i]}\"",
            "echo ${x:$y}",
            "echo ${x: -1}",
            "printf -v 'a[$(id)]' '%s' x",
            "tee >(sh)",
        ] {
            assert!(!read_only(command), "{command} should not count as read-only");
        }
    }

    #[test]
    fn quoted_spaces_and_specials_keep_their_words_apart() {
        let form = |command: &str| parse(command).commands[0].normalized();
        assert_eq!(form("rm -rf \"old files\""), "rm -rf old\\ files");
        assert_eq!(form("rm -rf 'old files'"), "rm -rf old\\ files");
        assert_eq!(form("rm -rf old\\ files"), "rm -rf old\\ files");
        assert_ne!(form("rm -rf \"old files\""), form("rm -rf old files"));
        assert_ne!(form("rm -rf '*.o'"), form("rm -rf *.o"));
        assert_eq!(form("echo \"$HOME\""), "echo $HOME");
        assert_eq!(form("rm -f ''"), "rm -f ''");
        assert_eq!(form("git status --short"), "git status --short");
        // A quoted NAME=value is no assignment.
        assert_eq!(parse("'A=1' ls").commands[0].command_words(), &["A=1".to_owned(), "ls".to_owned()]);
        assert_eq!(parse("A=1 ls").commands[0].command_words(), &["ls".to_owned()]);
    }

    #[test]
    fn always_patterns_use_first_words_or_the_exact_command() {
        let pattern = |command: &str| always_pattern(&parse(command).commands[0]);
        assert_eq!(pattern("git status --short"), "git status*");
        assert_eq!(pattern("cargo test -p core"), "cargo test*");
        assert_eq!(pattern("npm run build -- --watch"), "npm run build*");
        assert_eq!(pattern("python3 -m pytest tests/"), "python3 -m pytest*");
        assert_eq!(pattern("pytest -x"), "pytest*");
        assert_eq!(pattern("rm -rf *.o"), "rm -rf \\*.o");
        assert_eq!(pattern("rm -rf \"old files\""), "rm -rf old\\\\ files");
        assert_eq!(pattern("CI=1 make check"), "make check*");
        assert_eq!(escape("a*b?c\\"), "a\\*b\\?c\\\\");
    }
}
