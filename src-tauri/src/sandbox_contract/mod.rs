//! The VM sandbox contract from the VM part of the combined plan
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, Tier 0 at line 2587): pure, portable
//! library code with no VMs, hypervisors, network, new crates or host changes.
//!
//! Each submodule is one contract, built and tested against fakes on the shared foundation
//! (CORE-01 to CORE-08). Real backends, perimeters, sandbox-host and sandbox-link stay out.
//! The single writer of every path here is recorded in docs/combined-plan-agent-rollout.md,
//! section 16.

pub mod artifact_policy;
pub mod boundary_corpus;
pub mod canaries;
pub mod confinement;
pub mod connections;
pub mod declarations;
pub mod destinations;
pub mod dns_guard;
pub mod effects;
pub mod file_protocol;
pub mod files;
pub mod guest_policy;
pub mod models;
pub mod netprofile;
pub mod oci;
pub mod partition;
pub mod perimeter_install;
pub mod perimeter_os;
pub mod policy;
pub mod provider;
pub mod provider_evidence;
pub mod relay;
pub mod relay_broker;
pub mod relay_host;
pub mod relay_link;
pub mod relay_process;
pub mod remote;
pub mod remote_provider;
pub mod remote_ssh;
pub mod response;
pub mod signals;
pub mod trust_adapter;
pub mod untrusted;
pub mod vault;
pub mod views;

#[cfg(test)]
mod protocol_fuzz;
