//! Yougori's colours and the marks the screen draws with.
//!
//! The colours are the `yougori` CLI's (cli/src/cli_ui.rs) and the inference site's dark blue
//! (#9cc2ff). Text keeps the terminal's own colour and nothing paints a background, so the screen
//! sits on the person's dark terminal like the CLI does.
use ratatui::style::{Color, Modifier, Style};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Rgb(pub u8, pub u8, pub u8);

pub const BLUE: Rgb = Rgb(0x28, 0x6e, 0xea);
pub const SKY: Rgb = Rgb(0x38, 0xbd, 0xf8);
pub const CYAN: Rgb = Rgb(0x67, 0xe8, 0xf9);
pub const GREEN: Rgb = Rgb(0x4a, 0xde, 0x80);
pub const AMBER: Rgb = Rgb(0xfb, 0xbf, 0x24);
pub const RED: Rgb = Rgb(0xf8, 0x71, 0x71);
pub const GRAY: Rgb = Rgb(0x71, 0x71, 0x7a);
/// The inference site's light blue on dark pages: inline code and plain code.
pub const PALE: Rgb = Rgb(0x9c, 0xc2, 0xff);

/// The braille spinner the CLI turns while work runs.
pub const SPINNER: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
/// Milliseconds per spinner frame.
pub const SPIN_MS: u128 = 80;

/// How many colours the terminal shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Depth {
    /// 24-bit colour (`COLORTERM=truecolor` or `24bit`).
    True,
    /// The 256-colour palette.
    Ansi256,
    /// `NO_COLOR`: no colour at all; muted text is dimmed instead.
    None,
}

impl Depth {
    pub fn detect() -> Depth {
        let var = |name: &str| std::env::var(name).unwrap_or_default();
        if !var("NO_COLOR").is_empty() {
            return Depth::None;
        }
        Depth::from_colorterm(&var("COLORTERM"))
    }

    pub fn from_colorterm(value: &str) -> Depth {
        if value.eq_ignore_ascii_case("truecolor") || value.eq_ignore_ascii_case("24bit") {
            Depth::True
        } else {
            Depth::Ansi256
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Theme {
    pub depth: Depth,
}

impl Theme {
    pub fn new(depth: Depth) -> Theme {
        Theme { depth }
    }

    /// A brand colour as the terminal can show it.
    pub fn color(&self, c: Rgb) -> Color {
        match self.depth {
            Depth::True => Color::Rgb(c.0, c.1, c.2),
            Depth::Ansi256 => Color::Indexed(nearest_256(c)),
            Depth::None => Color::Reset,
        }
    }

    /// Any colour (from code highlighting or a terminal pane) as the terminal can show it.
    pub fn adapt(&self, color: Color) -> Color {
        match (self.depth, color) {
            (Depth::None, _) => Color::Reset,
            (Depth::Ansi256, Color::Rgb(r, g, b)) => Color::Indexed(nearest_256(Rgb(r, g, b))),
            (_, other) => other,
        }
    }

    pub fn fg(&self, c: Rgb) -> Style {
        Style::new().fg(self.color(c))
    }

    /// Secondary text: the CLI's gray, or dimmed text without colour.
    pub fn muted(&self) -> Style {
        match self.depth {
            Depth::None => Style::new().add_modifier(Modifier::DIM),
            _ => self.fg(GRAY),
        }
    }

    pub fn accent(&self) -> Style {
        self.fg(SKY)
    }

    pub fn good(&self) -> Style {
        self.fg(GREEN)
    }

    pub fn warn(&self) -> Style {
        self.fg(AMBER)
    }

    pub fn bad(&self) -> Style {
        self.fg(RED)
    }

    pub fn code(&self) -> Style {
        match self.depth {
            Depth::None => Style::new().add_modifier(Modifier::BOLD),
            _ => self.fg(PALE),
        }
    }

    pub fn bold(&self) -> Style {
        Style::new().add_modifier(Modifier::BOLD)
    }

    /// Green while there is room, amber when busy, red near the limit (the CLI's levels).
    pub fn level(&self, fraction: f64) -> Style {
        if fraction < 0.7 {
            self.muted()
        } else if fraction < 0.9 {
            self.warn()
        } else {
            self.bad()
        }
    }

    /// The colour between two brand colours, for the wordmark's blue-to-sky sweep.
    pub fn mix(&self, a: Rgb, b: Rgb, t: f64) -> Color {
        let t = t.clamp(0.0, 1.0);
        let c = |x: u8, y: u8| (f64::from(x) + (f64::from(y) - f64::from(x)) * t).round() as u8;
        self.color(Rgb(c(a.0, b.0), c(a.1, b.1), c(a.2, b.2)))
    }
}

/// The nearest colour of the 256-colour palette's cube and gray ramp.
pub fn nearest_256(c: Rgb) -> u8 {
    const LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];
    let level = |v: u8| -> usize {
        LEVELS
            .iter()
            .enumerate()
            .min_by_key(|(_, l)| (i32::from(**l) - i32::from(v)).abs())
            .map(|(i, _)| i)
            .unwrap_or(0)
    };
    let (r, g, b) = (level(c.0), level(c.1), level(c.2));
    let cube = (LEVELS[r], LEVELS[g], LEVELS[b]);
    let distance = |x: (u8, u8, u8)| {
        let d = |a: u8, b: u8| (i32::from(a) - i32::from(b)).pow(2);
        d(x.0, c.0) + d(x.1, c.1) + d(x.2, c.2)
    };
    let cube_index = 16 + 36 * r + 6 * g + b;
    // The gray ramp: 232 is 8, each step 10 brighter.
    let average = (u32::from(c.0) + u32::from(c.1) + u32::from(c.2)) / 3;
    let step = (average.saturating_sub(3) / 10).min(23) as u8;
    let gray = 8 + 10 * step;
    if distance((gray, gray, gray)) < distance(cube) {
        232 + step
    } else {
        cube_index as u8
    }
}

/// The spinner frame for this moment.
pub fn spinner(elapsed_ms: u128) -> &'static str {
    SPINNER[((elapsed_ms / SPIN_MS) % SPINNER.len() as u128) as usize]
}

/// The CLI's clock: 3.1s, 12s, 1m 05s, 1h 02m.
pub fn clock(elapsed: std::time::Duration) -> String {
    let s = elapsed.as_secs();
    if s < 10 {
        format!("{:.1}s", elapsed.as_secs_f64())
    } else if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m {:02}s", s / 60, s % 60)
    } else {
        format!("{}h {:02}m", s / 3600, s % 3600 / 60)
    }
}

/// The CLI's byte sizes: 512 B, 12 KB, 1.2 MB, 3.4 GB.
pub fn bytes(bytes: u64) -> String {
    match bytes {
        0..1024 => format!("{bytes} B"),
        1024..1_048_576 => format!("{:.0} KB", bytes as f64 / 1024.0),
        1_048_576..1_073_741_824 => format!("{:.1} MB", bytes as f64 / 1_048_576.0),
        _ => format!("{:.1} GB", bytes as f64 / 1_073_741_824.0),
    }
}

/// A count with thousands grouped: 1,240.
pub fn count(n: u64) -> String {
    let digits = n.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn colours_fall_back_to_the_256_palette_and_to_none() {
        assert_eq!(Theme::new(Depth::True).color(SKY), Color::Rgb(0x38, 0xbd, 0xf8));
        assert!(matches!(Theme::new(Depth::Ansi256).color(SKY), Color::Indexed(_)));
        assert_eq!(Theme::new(Depth::None).color(SKY), Color::Reset);
        // Gray lands on the gray ramp, pure colours on the cube.
        assert!(nearest_256(GRAY) >= 232);
        assert_eq!(nearest_256(Rgb(255, 0, 0)), 196);
        assert_eq!(Depth::from_colorterm("TrueColor"), Depth::True);
        assert_eq!(Depth::from_colorterm("24bit"), Depth::True);
        assert_eq!(Depth::from_colorterm(""), Depth::Ansi256);
    }

    #[test]
    fn clocks_sizes_and_counts_read_like_the_cli() {
        use std::time::Duration;
        assert_eq!(clock(Duration::from_millis(3100)), "3.1s");
        assert_eq!(clock(Duration::from_secs(12)), "12s");
        assert_eq!(clock(Duration::from_secs(65)), "1m 05s");
        assert_eq!(clock(Duration::from_secs(3720)), "1h 02m");
        assert_eq!(bytes(512), "512 B");
        assert_eq!(bytes(12 * 1024), "12 KB");
        assert_eq!(bytes(1_258_291), "1.2 MB");
        assert_eq!(count(1240), "1,240");
        assert_eq!(count(999), "999");
        assert_eq!(count(1_000_000), "1,000,000");
    }
}
