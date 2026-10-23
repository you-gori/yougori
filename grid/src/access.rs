//! Access Grid: a company's own hub for the credentials its people's agents use without ever
//! holding them.
//!
//! One trusted computer runs the hub. It keeps the company's API keys and tokens sealed with a
//! key from its OS vault, the people who may sign in (each with their own password and a
//! permission: member, approver, auditor or admin) and the rules that say who may use which
//! credential, for which methods and paths, and whether an approver decides first. People sign
//! in from their own computers with the admin's invite; their agents then ask the hub, through
//! `yougori access mcp`, to send a request with a credential. The hub sends it itself and hands
//! back the answer with the value hidden, so a credential never reaches an agent or its model
//! provider. Only a rule that explicitly allows it, plus an approver's decision each time, can
//! hand a value out. Every use, decision and change is logged.
pub mod activity;
pub mod backup;
pub mod forward;
pub mod hub;
pub mod member;
pub mod mint;
pub mod policy;
pub mod seal;
pub mod sigv4;
#[cfg(test)]
mod tests;
pub(crate) mod throttle;
