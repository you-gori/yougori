//! task: hands a self-contained job to a helper agent (one level: helpers cannot start helpers).
//! The helper's events carry `parent` = this call's id; its final reply comes back as the result.
use super::{required, text_arg, Output, Tool, ToolCtx};
use crate::native::permissions::Subject;
use crate::native::profiles::Kind;
use crate::native::shell;
use crate::native::util;
use crate::protocol::{ToolContent, ToolKind};
use async_trait::async_trait;
use serde_json::{json, Value};

pub struct Task {
    /// The helpers this profile may start: name and what it does.
    pub agents: Vec<(String, String)>,
}

impl Task {
    fn agent(&self, args: &Value) -> String {
        let named = text_arg(args, &["agent", "subagent", "subagent_type", "type", "profile"]).unwrap_or_default();
        let named = named.trim().to_ascii_lowercase();
        if named.is_empty() {
            return self.agents.first().map(|(n, _)| n.clone()).unwrap_or_default();
        }
        named
    }
}

#[async_trait]
impl Tool for Task {
    fn name(&self) -> &str {
        "task"
    }

    fn description(&self) -> String {
        let helpers: Vec<String> = self.agents.iter().map(|(name, what)| format!("{name}: {what}")).collect();
        format!(
            "Hand a self-contained job to a helper agent that works with its own fresh context and returns one report. \
             It knows nothing of this conversation: put everything it needs in the prompt. Helpers: {}.",
            helpers.join("; ")
        )
    }

    fn parameters(&self) -> Value {
        let names: Vec<&str> = self.agents.iter().map(|(n, _)| n.as_str()).collect();
        json!({
            "type": "object",
            "properties": {
                "description": { "type": "string", "description": "The job in three to six words." },
                "prompt": { "type": "string", "description": "The whole job: what to do or find, and what to report." },
                "agent": { "type": "string", "enum": names, "description": "Which helper." }
            },
            "required": ["description", "prompt", "agent"]
        })
    }

    fn kind(&self) -> ToolKind {
        ToolKind::Task
    }

    fn title(&self, args: &Value, _ctx: &ToolCtx<'_>) -> String {
        let what = text_arg(args, &["description", "title"]).unwrap_or_else(|| text_arg(args, &["prompt"]).unwrap_or_default());
        let agent = self.agent(args);
        let mut chars = agent.chars();
        let agent = chars.next().map(|c| c.to_uppercase().collect::<String>() + chars.as_str()).unwrap_or_default();
        format!("{agent}: {}", util::one_line(&what, 60))
    }

    fn subjects(&self, args: &Value, _ctx: &ToolCtx<'_>) -> Result<Vec<Subject>, String> {
        let agent = self.agent(args);
        Ok(vec![Subject::new("task", agent.clone(), shell::escape(&agent))])
    }

    async fn run(&self, args: Value, ctx: &ToolCtx<'_>) -> Result<Output, String> {
        let prompt = required(&args, &["prompt", "task", "instructions"])?;
        let agent = self.agent(&args);
        if !self.agents.iter().any(|(name, _)| *name == agent) {
            let names: Vec<&str> = self.agents.iter().map(|(n, _)| n.as_str()).collect();
            return Err(format!("There is no helper named {agent}. Helpers: {}.", names.join(", ")));
        }
        if ctx.parent.is_some() {
            return Err("A helper cannot start helpers of its own.".into());
        }
        let profile = match ctx.shared().profiles.get(&agent) {
            Some(profile) if profile.mode == Kind::Subagent => profile.clone(),
            _ => return Err(format!("The helper {agent} is not set up as a helper profile.")),
        };
        let report = crate::native::agent::run_helper(ctx.turn, profile, ctx.call.to_owned(), prompt).await?;
        Ok(Output {
            content: vec![ToolContent::Text { text: util::cut(&report, 4000).to_owned() }],
            text: report,
            ..Output::default()
        })
    }
}
