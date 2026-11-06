//! E01Z: bounded, deterministic protocol fuzzing of the host-side parsers that guest or
//! remote input reaches (docs/combined-gpu-memory-and-vm-sandbox-plan.md, VM-W50
//! "Protocol fuzzing, mutation tests and selected guard-failure injection", acceptance
//! "Parsers survive bounded fuzz corpus; single-guard failures are detected or contained
//! where claimed"; VM §12.1 Tier 0, §12.2 VM-P10 and VM-P28; VM-R99). The host part of
//! VM-W50. E01Y extends it to the parsers E01Z left out: the relay's response reader, the
//! perimeter stores' read-back of host firewall listings, and the strict readers of two
//! kinds of durable host state.
//!
//! Test-only code: the whole module is compiled under `cfg(test)`. No crate is added, as
//! the plan's `cargo-fuzz` row allows ("the mutation harness works without it"). Nothing
//! here opens a socket, resolves a name, runs a VM, starts a process or runs a firewall
//! command; the file protocol dispatcher, the SSH classifier and the fresh-root journal's
//! launch path get scratch directories under the harness's temporary directory, as their
//! own tests do, and the perimeter stores get fake command ports.
//!
//! - `rng`: SplitMix64, the one seeded generator, so every run replays exactly.
//! - `mutate`: the mutators (bit flips, byte insertion and deletion, boundary values
//!   written into length and count fields, splices of valid seeds, truncation) and what
//!   each target tells them about its format (`mutate::Grammar`).
//! - `driver`: runs a target's regression corpus first, then its seeds, then a fixed
//!   number of mutated inputs, each under `catch_unwind`. A panic or a broken property
//!   fails the test with the input in hex and a shrunk minimal input.
//! - The targets, each with its seed corpus (built with the module's own builders where
//!   it has them), its regression corpus of byte constants and its fixed budget:
//!   `dns` (the DNS guard's query parser and response encoder), `file_protocol` (the
//!   strict request decoder, the request encoder and the dispatcher's bounds), `relay`
//!   (the request reader, split-independence included), `relay_response` (the response
//!   reader for GET and HEAD, split-independence included), `perimeter_nft` (the
//!   nftables store's `nft -j` table listing and list of tables), `perimeter_pf` (the pf
//!   store's anchor listing), `remote_ssh` (`parse_known_hosts` and `classify`),
//!   `root_journal` (the strict reader of the fresh-root journal), `trust_record` (the
//!   strict reader of the trust stream's record) and `untrusted` (the strict serde reader
//!   of a normalizer's report).
//! - Shared by targets: `perimeter_rules` (random valid perimeter rule sets, their
//!   grants, and the checks of a snapshot read back) and `strict_json` (whether accepted
//!   JSON denotes exactly the record read, and the edits a strict reader must refuse).
//!
//! Every target checks, for every input: no panic; the same input gives the same result;
//! the documented size limits hold; and where it applies, that random splits of the input
//! give the same result and that what an encoder writes parses back to the same message.
//! The per-target notes list the rest.
//!
//! The WFP store is not a target: its parser reads typed filter specifications from the
//! port, never bytes or text.
//!
//! Limits: the fuzzer is not coverage-guided, so it reaches only what the seeds,
//! dictionaries and field finders steer it to; each target asserts which outcomes its run
//! reached, so a run that stops reaching them fails. `catch_unwind` cannot catch an abort
//! (a stack overflow or an allocation failure). The budgets keep the module within about
//! 30 seconds in a debug build; they find shallow faults, not deep ones. A finding is kept
//! as a regression input under `#[ignore]` with its reason, and the target is not fixed
//! here.

#![cfg(test)]

/// Returns `Err` with the formatted message unless `condition` holds: a broken property,
/// reported with the input that broke it.
macro_rules! ensure {
    ($condition:expr, $($message:tt)+) => {
        if !$condition {
            return Err(format!($($message)+));
        }
    };
}

mod driver;
mod mutate;
mod perimeter_rules;
mod rng;
mod strict_json;

mod dns;
mod file_protocol;
mod perimeter_nft;
mod perimeter_pf;
mod relay;
mod relay_response;
mod remote_ssh;
mod root_journal;
mod trust_record;
mod untrusted;
