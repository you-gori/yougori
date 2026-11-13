//! Profiles: what an agent is (its prompt, tools, permissions, step limit and sampling), as
//! files with TOML front matter between `+++` lines and a markdown prompt after them.
//!
//! The built-in profiles are embedded: `yougori` (the default: builds and edits), `plan`
//! (read-only, plans before edits), and the helpers `explore` (read-only) and `general`. Files in
//! `<state_dir>/profiles/*.md` replace a built-in profile of the same name or add new ones.
use super::permissions::{wildcard, Rule};
use serde::Deserialize;
use std::path::Path;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A mode the person works in.
    #[default]
    Primary,
    /// A helper the task tool starts.
    Subagent,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Profile {
    pub name: String,
    pub description: String,
    pub mode: Kind,
    /// Tool names or patterns; `*` offers every tool, MCP tools included.
    pub tools: Vec<String>,
    pub permissions: Vec<Rule>,
    /// Model calls per prompt before the closing message.
    pub steps: u32,
    pub temperature: Option<f64>,
    pub top_p: Option<f64>,
    /// The helpers its task tool may start.
    pub subagents: Vec<String>,
    pub prompt: String,
    /// `built-in` or the file it came from.
    pub source: String,
}

impl Profile {
    pub fn offers(&self, tool: &str) -> bool {
        self.tools.iter().any(|pattern| wildcard(pattern, tool))
    }

    /// The name as a title: `Plan`.
    pub fn title(&self) -> String {
        let mut chars = self.name.chars();
        match chars.next() {
            Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
            None => String::new(),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Front {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    mode: Kind,
    #[serde(default = "every_tool")]
    tools: Vec<String>,
    #[serde(default)]
    permissions: Vec<Rule>,
    #[serde(default = "default_steps")]
    steps: u32,
    #[serde(default)]
    temperature: Option<f64>,
    #[serde(default)]
    top_p: Option<f64>,
    #[serde(default)]
    subagents: Vec<String>,
}

fn every_tool() -> Vec<String> {
    vec!["*".into()]
}

fn default_steps() -> u32 {
    50
}

const BUILT_IN: [&str; 4] = [
    include_str!("profiles/yougori.md"),
    include_str!("profiles/plan.md"),
    include_str!("profiles/explore.md"),
    include_str!("profiles/general.md"),
];

/// Reads a profile file's text.
pub fn parse(text: &str, source: &str) -> Result<Profile, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text).replace("\r\n", "\n");
    let rest = text
        .strip_prefix("+++\n")
        .ok_or_else(|| format!("{source}: a profile starts with a line of +++, then its settings, then +++."))?;
    let (front, body) = match rest.find("\n+++\n") {
        Some(at) => (&rest[..at], &rest[at + 5..]),
        None => match rest.strip_suffix("\n+++") {
            Some(front) => (front, ""),
            None => return Err(format!("{source}: the settings are not closed with a line of +++.")),
        },
    };
    let front: Front = toml::from_str(front).map_err(|e| format!("{source}: {}", e.to_string().trim()))?;
    let name = front.name.trim().to_owned();
    if name.is_empty()
        || name.len() > 40
        || !name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(format!("{source}: the name must be 1 to 40 lowercase letters, digits, - or _."));
    }
    if !(1..=1000).contains(&front.steps) {
        return Err(format!("{source}: steps must be between 1 and 1000."));
    }
    if front.temperature.is_some_and(|t| !(0.0..=2.0).contains(&t)) {
        return Err(format!("{source}: temperature must be between 0 and 2."));
    }
    if front.top_p.is_some_and(|p| !(p > 0.0 && p <= 1.0)) {
        return Err(format!("{source}: top_p must be above 0 and at most 1."));
    }
    let prompt = body.trim().to_owned();
    if prompt.is_empty() {
        return Err(format!("{source}: the prompt after the settings is empty."));
    }
    Ok(Profile {
        name,
        description: front.description.trim().to_owned(),
        mode: front.mode,
        tools: front.tools,
        permissions: front.permissions,
        steps: front.steps,
        temperature: front.temperature,
        top_p: front.top_p,
        subagents: front.subagents,
        prompt,
        source: source.to_owned(),
    })
}

#[derive(Clone, Debug)]
pub struct Profiles {
    list: Vec<Profile>,
}

impl Profiles {
    pub fn built_in() -> Profiles {
        let list = BUILT_IN.iter().map(|text| parse(text, "built-in").expect("a built-in profile is valid")).collect();
        Profiles { list }
    }

    /// The built-in profiles with the files in `folder` laid over them. Problems with a file
    /// come back as warnings; the file is then left out.
    pub fn load(folder: &Path) -> (Profiles, Vec<String>) {
        let mut profiles = Profiles::built_in();
        let mut warnings = Vec::new();
        let Ok(entries) = std::fs::read_dir(folder) else { return (profiles, warnings) };
        let mut files: Vec<_> = entries
            .filter_map(Result::ok)
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("md")) && p.is_file())
            .collect();
        files.sort();
        for file in files {
            let source = file.display().to_string();
            let text = match std::fs::read_to_string(&file) {
                Ok(text) => text,
                Err(e) => {
                    warnings.push(format!("Profile {source} was not read: {e}"));
                    continue;
                }
            };
            match parse(&text, &source) {
                Ok(profile) => match profiles.list.iter().position(|p| p.name == profile.name) {
                    Some(at) => profiles.list[at] = profile,
                    None => profiles.list.push(profile),
                },
                Err(e) => warnings.push(format!("Profile left out: {e}")),
            }
        }
        (profiles, warnings)
    }

    pub fn get(&self, name: &str) -> Option<&Profile> {
        self.list.iter().find(|p| p.name == name)
    }

    /// The modes the person can work in.
    pub fn primary(&self) -> Vec<&Profile> {
        self.list.iter().filter(|p| p.mode == Kind::Primary).collect()
    }

    /// The profile `name` as the person's mode, or a plain error naming the choices.
    pub fn mode(&self, name: &str) -> Result<&Profile, String> {
        let names = self.primary().iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(", ");
        match self.get(name) {
            Some(profile) if profile.mode == Kind::Primary => Ok(profile),
            Some(_) => Err(format!("The profile {name} is a helper for the task tool, not a mode to work in. Modes: {names}.")),
            None => Err(format!("Our own agent has no profile named {name}. Modes: {names}.")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::permissions::Action;

    #[test]
    fn built_in_profiles_parse() {
        let profiles = Profiles::built_in();
        let names: Vec<_> = profiles.list.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["yougori", "plan", "explore", "general"]);
        let yougori = profiles.get("yougori").unwrap();
        assert_eq!((yougori.mode, yougori.steps), (Kind::Primary, 50));
        assert!(yougori.offers("bash") && yougori.offers("github_create_issue"));
        assert_eq!(yougori.subagents, vec!["explore", "general"]);
        let plan = profiles.get("plan").unwrap();
        assert!(plan.offers("read") && plan.offers("todowrite") && !plan.offers("edit") && !plan.offers("write"));
        assert_eq!(profiles.get("explore").unwrap().mode, Kind::Subagent);
        assert_eq!(profiles.primary().len(), 2);
        assert!(profiles.mode("explore").unwrap_err().contains("helper"));
        assert!(profiles.mode("pentestgpt").unwrap_err().contains("no profile named pentestgpt"));
        for profile in &profiles.list {
            assert!(profile.prompt.len() > 200, "{} has a real prompt", profile.name);
        }
    }

    #[test]
    fn changing_git_settings_asks_even_where_files_change_freely() {
        use crate::native::permissions::{decide, Subject, Vars};
        let vars = Vars { cwd: "/work/app".into(), state: "/home/u/.yougori".into(), home: "/home/u".into() };
        let profiles = Profiles::built_in();
        for name in ["yougori", "general"] {
            let rules = &profiles.get(name).unwrap().permissions;
            for tool in ["write", "edit"] {
                let action = |path: &str| decide(rules, &Subject::new(tool, path, ""), &vars);
                assert_eq!(action("/work/app/src/main.rs"), Some(Action::Allow), "{name} {tool}");
                assert_eq!(action("/work/app/.gitignore"), Some(Action::Allow), "{name} {tool}");
                for git in ["/work/app/.git/config", "/work/app/.git/hooks/pre-commit", "/work/app/.git", "/work/app/vendor/lib/.git/config", "/work/app/sub/.git"] {
                    assert_eq!(action(git), Some(Action::Ask), "{name} {tool} {git}");
                }
            }
        }
    }

    #[test]
    fn a_file_profile_parses_and_overrides() {
        let text = "+++\nname = \"yougori\"\ndescription = \"Mine\"\ntools = [\"read\", \"bash\"]\nsteps = 7\ntemperature = 0.2\n\n[[permissions]]\ntool = \"bash\"\npattern = \"git *\"\naction = \"allow\"\n+++\nDo things.\n";
        let profile = parse(text, "mine.md").unwrap();
        assert_eq!(profile.steps, 7);
        assert_eq!(profile.temperature, Some(0.2));
        assert_eq!(profile.permissions[0].action, Action::Allow);
        assert_eq!(profile.prompt, "Do things.");
        let folder = tempfile::tempdir().unwrap();
        std::fs::write(folder.path().join("mine.md"), text.replace('\n', "\r\n")).unwrap();
        std::fs::write(folder.path().join("broken.md"), "+++\nname = \"x\"\nsteps = \"many\"\n+++\nHi").unwrap();
        std::fs::write(folder.path().join("notes.txt"), "ignored").unwrap();
        let (profiles, warnings) = Profiles::load(folder.path());
        assert_eq!(profiles.get("yougori").unwrap().prompt, "Do things.");
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("broken.md"));
    }

    #[test]
    fn bad_profiles_say_what_is_wrong() {
        assert!(parse("name = \"x\"", "a").unwrap_err().contains("starts with a line of +++"));
        assert!(parse("+++\nname = \"x\"\n", "a").unwrap_err().contains("not closed"));
        assert!(parse("+++\nname = \"X Y\"\n+++\nHi", "a").unwrap_err().contains("lowercase"));
        assert!(parse("+++\nname = \"x\"\nsteps = 0\n+++\nHi", "a").unwrap_err().contains("steps"));
        assert!(parse("+++\nname = \"x\"\n+++\n  ", "a").unwrap_err().contains("empty"));
        assert!(parse("+++\nname = \"x\"\ncolour = 1\n+++\nHi", "a").unwrap_err().contains("colour"));
        assert!(parse("+++\nname = \"x\"\n[[permissions]]\ntool = \"bash\"\naction = \"maybe\"\n+++\nHi", "a").is_err());
    }
}
