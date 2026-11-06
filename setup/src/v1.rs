//! Compiles the existing v1 template format into the shared plan, so old packages keep working.
//!
//! The clients keep their v1 parser; this module takes what it already produces, in neutral
//! form, and plans it exactly as a format 2 package: every environment becomes an environment
//! resource, every `public:` entry a public address, every connection a connection, with the
//! same questions, tools, steps and outputs and nothing added. A v1 package therefore gets the
//! same review, the same determinism and the same lock as a format 2 one, and asks nothing new.
use crate::{
    dto::Diagnostic,
    format::{Checked, CheckedOutput, CheckedPublic, CheckedStep, FormatVersion, LegacyConnection, Models, Project, Question, Requires, Retention, Template, ToolUse},
    plan::{self, Answers, Host, Package, Plan},
};
use serde_yaml_ng::Value as Yaml;
use std::collections::BTreeMap;

/// A v1 template as the client's parser read it: no YAML is parsed here.
#[derive(Clone, Debug, Default)]
pub struct LegacyTemplate {
    pub name: String,
    pub version: String,
    pub title: Option<String>,
    pub summary: Option<String>,
    pub requires: Requires,
    /// The `project:` name of the project file.
    pub project: String,
    /// Environments as written in the project file, placeholders included.
    pub environments: BTreeMap<String, Yaml>,
    pub connections: Vec<LegacyConnection>,
    pub questions: Vec<Question>,
    pub tools: Vec<ToolUse>,
    pub public: Vec<CheckedPublic>,
    pub steps: Vec<CheckedStep>,
    pub outputs: Vec<CheckedOutput>,
    pub models: Option<Models>,
}

impl LegacyTemplate {
    /// The same template in the form the planner takes.
    pub fn checked(&self) -> Checked {
        Checked {
            format: FormatVersion::V1,
            template: Template {
                format_version: None,
                kind: Some("template".into()),
                name: Some(self.name.clone()),
                title: self.title.clone(),
                summary: self.summary.clone(),
                version: Some(self.version.clone()),
                requires: self.requires.clone(),
                ..Template::default()
            },
            project_path: crate::format::PROJECT_FILE.to_owned(),
            project_text: String::new(),
            project: Project { format_version: None, project: self.project.clone(), environments: self.environments.clone(), ..Project::default() },
            profile: None,
            questions: self.questions.clone(),
            capabilities: Vec::new(),
            bindings: Vec::new(),
            tools: self.tools.clone(),
            environments: self.environments.clone(),
            connections: self.connections.clone(),
            public: self.public.clone(),
            resources: BTreeMap::new(),
            steps: self.steps.clone(),
            outputs: self.outputs.clone(),
            retention: Retention::default(),
            views: Vec::new(),
            models: self.models.clone(),
        }
    }

    /// The package the planner takes, with the Hub item and digest when known.
    pub fn package(&self, item: Option<String>, digest: Option<String>) -> Package {
        Package { checked: self.checked(), components: BTreeMap::new(), item, digest }
    }
}

/// The plan of a v1 template with these answers on this computer: the same plan a format 2
/// package with the same content gets.
pub fn compile_v1(legacy: &LegacyTemplate, answers: &Answers, host: &Host) -> Result<Plan, Vec<Diagnostic>> {
    plan::plan(&legacy.package(None, None), answers, host)
}
