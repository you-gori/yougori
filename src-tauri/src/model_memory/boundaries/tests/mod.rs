//! Tests of the five boundaries and the GPU §1 flow (T15), on a manual clock, over the
//! CORE-04 coordinator and the CORE-03 ledger, with fakes for the catalog, the transfer
//! executor, the runner and the API, CLI and UI adapter; and of the catalog store and the
//! portable executor over the committed CORE-02 catalog, P01 importer and P03 executor.

mod committed;
mod support;

mod boundaries;
mod demand;
mod flow;
mod governor;
mod kv;
mod kv_evidence;
mod kv_sessions;
mod kv_trim;
mod kv_waits;
mod lifecycle_events;
mod portable;
mod reload;
mod reload_resume;
mod store;
