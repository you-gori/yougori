//! The VM sandbox runtime layer from the VM part of the combined plan
//! (docs/combined-gpu-memory-and-vm-sandbox-plan.md, Tier 0 at line 2762): pure, portable
//! library code with no VMs, hypervisors, network, new crates or host changes, built on the
//! shared foundation (CORE-01 to CORE-08) and beside the contract layer in
//! `sandbox_contract`. Real backends, perimeters, sandbox-host and sandbox-link stay out.
//! The single writer of every path here is recorded in docs/combined-plan-agent-rollout.md,
//! section 16.

pub mod audit;
pub mod backend;
pub mod bench;
pub mod doctor;
pub mod evidence_matrix;
pub mod firecracker;
pub mod guest_files;
pub mod guest_image;
pub mod host;
pub mod host_checks;
pub mod integration;
pub mod lifecycle;
pub mod link;
pub mod link_transport;
pub mod probes;
pub mod qemu;
#[cfg(windows)]
pub mod hcs;
pub mod qemu_host;
pub mod trust;
pub mod trust_scan;
pub mod vm_service;
