//! Code highlighting: syntect's bundled grammars (pure-Rust regex engine) with Yougori's own
//! colour scheme built from the brand colours. Code still streaming in is highlighted from where
//! the last frame stopped, so a long block costs only its new lines.
use super::theme::{self, Rgb, Theme};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Span;
use std::str::FromStr;
use std::sync::OnceLock;
use syntect::highlighting::{
    Color as SynColor, FontStyle, HighlightIterator, HighlightState, Highlighter, ScopeSelectors, StyleModifier,
    Theme as SynTheme, ThemeItem, ThemeSettings,
};
use syntect::parsing::{ParseState, ScopeStack, SyntaxReference, SyntaxSet};

/// Lines past this many in one block are shown without colour.
const MAX_LINES: usize = 3000;
/// Marks "the terminal's own colour" in the scheme.
const DEFAULT_FG: SynColor = SynColor { r: 1, g: 2, b: 3, a: 0 };

static SYNTAXES: OnceLock<SyntaxSet> = OnceLock::new();
static SCHEME: OnceLock<SynTheme> = OnceLock::new();

fn syntaxes() -> &'static SyntaxSet {
    SYNTAXES.get_or_init(SyntaxSet::load_defaults_newlines)
}

fn scheme() -> &'static SynTheme {
    SCHEME.get_or_init(build_scheme)
}

/// Loads the grammars in the background so the first code block does not wait for them.
pub fn warm() {
    let _ = std::thread::Builder::new().name("yougori-highlight".into()).spawn(|| {
        syntaxes();
        scheme();
    });
}

fn build_scheme() -> SynTheme {
    let rgb = |c: Rgb| Some(SynColor { r: c.0, g: c.1, b: c.2, a: 0xff });
    let item = |scopes: &str, foreground: Option<SynColor>, font: FontStyle| ThemeItem {
        scope: ScopeSelectors::from_str(scopes).unwrap_or_default(),
        style: StyleModifier { foreground, background: None, font_style: Some(font) },
    };
    let plain = FontStyle::empty();
    SynTheme {
        name: Some("Yougori".into()),
        author: None,
        settings: ThemeSettings { foreground: Some(DEFAULT_FG), ..ThemeSettings::default() },
        scopes: vec![
            item("comment, punctuation.definition.comment", rgb(theme::GRAY), FontStyle::ITALIC),
            item("string, punctuation.definition.string", rgb(theme::GREEN), plain),
            item("constant.character.escape, string.regexp", rgb(theme::CYAN), plain),
            item("constant.numeric, constant.language, constant.character, constant.other, support.constant", rgb(theme::AMBER), plain),
            item("keyword, storage, variable.language", rgb(theme::SKY), plain),
            item("keyword.operator, punctuation", Some(DEFAULT_FG), plain),
            item("keyword.operator.word, keyword.operator.logical.python", rgb(theme::SKY), plain),
            item("entity.name.function, support.function, variable.function", rgb(theme::PALE), plain),
            item("entity.name.type, entity.name.class, entity.name.struct, entity.name.enum, entity.name.trait, support.type, support.class, entity.other.inherited-class", rgb(theme::CYAN), plain),
            item("entity.name.tag", rgb(theme::SKY), plain),
            item("entity.other.attribute-name", rgb(theme::PALE), plain),
            item("markup.heading", rgb(theme::SKY), FontStyle::BOLD),
            item("markup.bold", None, FontStyle::BOLD),
            item("markup.italic", None, FontStyle::ITALIC),
            item("markup.inserted", rgb(theme::GREEN), plain),
            item("markup.deleted", rgb(theme::RED), plain),
            item("meta.diff.header, meta.diff.range, meta.diff.index", rgb(theme::GRAY), plain),
            item("invalid", rgb(theme::RED), plain),
        ],
    }
}

/// The grammar for a fence's language word, with the usual short names.
pub fn find(language: &str) -> Option<&'static SyntaxReference> {
    let word = language.trim().split(|c: char| c.is_whitespace() || c == ',' || c == '{').next().unwrap_or("");
    let word = word.trim_start_matches('.').to_ascii_lowercase();
    if word.is_empty() || matches!(word.as_str(), "text" | "txt" | "plain" | "plaintext" | "output" | "log") {
        return None;
    }
    let token = match word.as_str() {
        "ts" | "tsx" | "typescript" | "mts" | "cts" | "jsx" | "javascript" | "node" | "mjs" | "cjs" => "js",
        "sh" | "bash" | "zsh" | "shell" | "console" | "shellscript" | "terminal" => "sh",
        "py" | "python" | "python3" | "py3" => "py",
        "rs" | "rust" => "rs",
        "golang" | "go" => "go",
        "c++" | "cpp" | "cxx" | "hpp" => "cpp",
        "cs" | "csharp" | "c#" => "cs",
        "rb" | "ruby" => "rb",
        "yml" | "yaml" => "yaml",
        "md" | "markdown" => "md",
        "patch" | "diff" => "diff",
        "html" | "htm" | "xhtml" => "html",
        "objc" | "objective-c" => "m",
        "make" | "makefile" => "makefile",
        other => other,
    };
    let set = syntaxes();
    set.find_syntax_by_token(token).or_else(|| set.find_syntax_by_name(language.trim()))
}

fn to_style(style: syntect::highlighting::Style, theme: &Theme) -> Style {
    let mut out = Style::new();
    if style.foreground != DEFAULT_FG {
        let c = style.foreground;
        out = out.fg(theme.adapt(Color::Rgb(c.r, c.g, c.b)));
    }
    if style.font_style.contains(FontStyle::BOLD) {
        out = out.add_modifier(Modifier::BOLD);
    }
    if style.font_style.contains(FontStyle::ITALIC) {
        out = out.add_modifier(Modifier::ITALIC);
    }
    if style.font_style.contains(FontStyle::UNDERLINE) {
        out = out.add_modifier(Modifier::UNDERLINED);
    }
    out
}

/// One code block's highlighting, kept between frames.
pub struct Code {
    language: String,
    syntax: Option<&'static SyntaxReference>,
    /// The complete lines highlighted so far.
    done: String,
    lines: Vec<Vec<Span<'static>>>,
    state: Option<(ParseState, HighlightState)>,
    /// The grammar failed, or the block passed the limit: the rest has no colour.
    stopped: bool,
}

impl Code {
    pub fn new(language: &str) -> Code {
        Code {
            language: language.to_owned(),
            syntax: find(language),
            done: String::new(),
            lines: Vec::new(),
            state: None,
            stopped: false,
        }
    }

    pub fn language(&self) -> &str {
        &self.language
    }

    fn reset(&mut self) {
        self.done.clear();
        self.lines.clear();
        self.state = None;
        self.stopped = false;
    }

    fn plain(line: &str, theme: &Theme) -> Vec<Span<'static>> {
        vec![Span::styled(line.to_owned(), theme.code())]
    }

    /// The block's lines, highlighted; each source line is one list of spans.
    pub fn lines(&mut self, code: &str, theme: &Theme) -> Vec<Vec<Span<'static>>> {
        let Some(syntax) = self.syntax else {
            return code.split('\n').map(|line| Code::plain(line, theme)).collect();
        };
        if !code.starts_with(self.done.as_str()) {
            self.reset();
        }
        let set = syntaxes();
        let highlighter = Highlighter::new(scheme());
        if self.state.is_none() && !self.stopped {
            self.state = Some((ParseState::new(syntax), HighlightState::new(&highlighter, ScopeStack::new())));
        }
        let rest = &code[self.done.len()..];
        let mut consumed = 0;
        for line in rest.split_inclusive('\n') {
            if !line.ends_with('\n') {
                break;
            }
            let shown = line.trim_end_matches(['\n', '\r']);
            let highlighted = match self.state.as_mut() {
                Some((parse, highlight)) if self.lines.len() < MAX_LINES => {
                    highlight_line(parse, highlight, &highlighter, set, line, theme)
                }
                _ => None,
            };
            let spans = highlighted.unwrap_or_else(|| {
                // Past the limit, or the grammar failed on this text: the rest has no colour.
                self.state = None;
                self.stopped = true;
                Code::plain(shown, theme)
            });
            self.lines.push(spans);
            consumed += line.len();
        }
        self.done.push_str(&rest[..consumed]);
        let mut lines = self.lines.clone();
        let partial = &rest[consumed..];
        // The last line (without a newline yet) is highlighted on a copy of the state.
        let last = if let Some((parse, highlight)) = self.state.as_ref().filter(|_| lines.len() < MAX_LINES) {
            let (mut parse, mut highlight) = (parse.clone(), highlight.clone());
            let with_newline = format!("{partial}\n");
            highlight_line(&mut parse, &mut highlight, &highlighter, set, &with_newline, theme)
                .unwrap_or_else(|| Code::plain(partial, theme))
        } else {
            Code::plain(partial, theme)
        };
        lines.push(last);
        lines
    }
}

fn highlight_line(
    parse: &mut ParseState,
    highlight: &mut HighlightState,
    highlighter: &Highlighter<'_>,
    set: &SyntaxSet,
    line: &str,
    theme: &Theme,
) -> Option<Vec<Span<'static>>> {
    let ops = parse.parse_line(line, set).ok()?;
    let mut spans: Vec<Span<'static>> = Vec::new();
    for (style, text) in HighlightIterator::new(highlight, &ops, line, highlighter) {
        let text = text.trim_end_matches(['\n', '\r']);
        if text.is_empty() {
            continue;
        }
        let style = to_style(style, theme);
        match spans.last_mut() {
            Some(last) if last.style == style => last.content.to_mut().push_str(text),
            _ => spans.push(Span::styled(text.to_owned(), style)),
        }
    }
    Some(spans)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ui::theme::Depth;

    #[test]
    fn highlights_known_languages_and_streams_from_where_it_stopped() {
        let theme = Theme::new(Depth::True);
        assert!(find("rust").is_some());
        assert!(find("ts").is_some(), "TypeScript borrows the JavaScript grammar");
        assert!(find("text").is_none());
        let mut code = Code::new("rust");
        let first = code.lines("fn main() {\n    let x = 1;", &theme);
        assert_eq!(first.len(), 2);
        let keyword = first[0].iter().find(|s| s.content == "fn").expect("fn is its own span");
        assert_eq!(keyword.style.fg, Some(Color::Rgb(0x38, 0xbd, 0xf8)));
        let more = code.lines("fn main() {\n    let x = 1;\n}\n", &theme);
        assert_eq!(more.len(), 4);
        assert_eq!(code.lines.len(), 3, "complete lines are kept");
        let text: String = more[1].iter().map(|s| s.content.as_ref()).collect();
        assert_eq!(text, "    let x = 1;");
    }

    #[test]
    fn unknown_languages_are_plain_code() {
        let theme = Theme::new(Depth::True);
        let mut code = Code::new("");
        let lines = code.lines("a\nb", &theme);
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0][0].style, theme.code());
    }
}
