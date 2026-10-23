pub mod catalog;
pub mod decisions;
pub mod architecture_support;
pub mod model_invocation;
pub mod client;
pub mod parse;
pub mod skills;
pub mod wire;
pub mod manifest;
pub mod workload;
pub mod public;
pub mod storage;
pub mod overview;
pub mod project_files;
pub mod launcher_state;
pub mod terminal;
pub mod terminal_stream;
pub mod container_tools;
mod tool_public_access;
mod tool_credentials;
pub mod tool_sharing;
pub mod sandbox_stop;
#[path = "launcher/ui.rs"]
pub mod cli_ui;
#[path = "launcher/composer.rs"]
pub mod composer;
pub mod presentation;
pub mod doctor;
pub mod update;
pub mod release_notice;
pub mod downloads;
pub mod discovery;
pub mod execution;
pub mod logs;
pub mod vault;
pub mod access;
pub mod model_auth;
pub mod network;
pub mod grid;
pub mod grids;
pub mod rollout;
pub mod closed_bounty;
#[path = "../../distribution.rs"]
pub mod distribution;
pub mod model_registry;
pub mod confidential;
pub mod bounty;
pub mod bounty_practice;
mod bounty_console;
pub mod legacy_names;
pub mod bounty_map;
pub mod security;
pub mod hub;
#[cfg(test)]
mod help_coverage;

pub const SKILL: &str = include_str!("../../skills/yougori/SKILL.txt");
pub const GUIDE: &str = include_str!("../../skills/yougori/references/cli.txt");
