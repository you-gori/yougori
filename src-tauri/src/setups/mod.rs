//! Setups: the engine-owned registry, operation journal, resource handlers, recovery and read-only
//! adoption behind My setups (template platform plan, sections 4, 6 and 8;
//! docs/template-platform/adr-0002-setup-engine.md).
//!
//! The engine is the one writer of setup state. The desktop and the CLI read it and ask for
//! changes through the same calls, so they never race separate state machines.
mod adopt;
mod backups;
mod export;
pub(crate) mod commands;
mod events;
mod grids;
mod handler;
mod hub_tools;
mod job_worker;
mod jobs;
mod journal;
mod local_models;
mod migration;
mod model;
mod ordinary;
mod package;
mod permissions;
mod planning;
mod product;
mod schedules;
mod service;
mod share;
mod store;
mod telemetry;
mod views;
mod vm_sandbox;
mod watch;
#[cfg(test)]
mod tests;

use crate::{store::PlatformStore, AppHandle};
use std::sync::Arc;
use tauri::Manager;

pub(crate) use commands::wire_fault;

/// Where templates come from, for planning.
pub(crate) struct Sources {
    pub hub: Arc<dyn planning::Hub>,
}
pub(crate) use service::Service;

/// Opens the setup registry beside the platform state and settles what a previous engine left
/// unfinished. A registry that can't be read leaves the service reporting why, and startup goes
/// on: nothing a setup runs depends on this file being readable.
pub(crate) fn start(app: &AppHandle) {
    let store = app.state::<PlatformStore>();
    let mut handlers = handler::Handlers::default();
    // Sandboxes, volumes, publications and connections, through the engine's project engine.
    let ordinary = ordinary::Ordinary::new(Arc::new(ordinary::EngineProjects::new(app.clone())), store.data_folder("setups").join("projects"));
    // Neo Grid: the grid, its computers and its models, through the Neo Grid product.
    let grids = grids::Grids::new(Arc::new(grids::EngineGrids::new(app.clone())));
    // Finite jobs and what they produce, through a Grid Core realm of each setup's own. The worker
    // loops stay off until a setup that declares jobs is applied.
    let finite = jobs::Jobs::new(Arc::new(jobs::EngineJobs::new(app.clone(), store.data_folder("setups").join("jobs"))));
    let event_urls = finite.urls();
    // VM sandboxes: the restricted VM, its routes and its staged workspace, through the engine's
    // VM sandbox path (`sandbox_vm`).
    let vms = vm_sandbox::VmSandboxHandler::new(Arc::new(vm_sandbox::EngineVmSandboxes::new(app.clone())))
        .with_packages(store.data_folder("setups").join("projects"));
    for each in ordinary.handlers().into_iter().chain(grids.handlers()).chain(finite.handlers()).chain(vms.handlers()) {
        handlers.register(each);
    }
    // What a setup's jobs handed back and printed, read through the same realm the handlers use.
    app.manage(finite.clone());
    let service = Arc::new(Service::open(&store.data_folder("setups"), &store.data_folder(""), handlers));
    if let Some(problem) = service.availability() {
        eprintln!("Setups are unavailable: {}", problem.message);
    }
    app.manage(service.clone());
    app.manage(Sources { hub: Arc::new(planning::EngineHub::new(store.data_folder("setups").join("hub-cache"))) });
    // Scheduled backups: the times live in the registry, so a restart knows what was missed.
    // Nothing starts once the engine is closing (`automation::shutdown_signal`).
    let worker = backups::Backups::new(
        service.clone(),
        Arc::new(backups::EngineSandboxes::new(app.clone())),
        store.data_folder("setups").join("backups"),
    );
    let scheduler = schedules::Scheduler::new(service.clone(), backups::Work::new(service.clone(), worker.clone()));
    service.wire_backups(worker, scheduler.clone());
    let stopping = crate::automation::shutdown_signal(app);
    tauri::async_runtime::spawn(async move { scheduler.run(stopping).await });
    // Health check, Health and logs and Notifications: a look once a minute at the setups that
    // ask for one (`setups::watch`).
    let watcher = watch::Watcher::new(service.clone(), Arc::new(watch::EngineEffects { app: app.clone(), folder: store.data_folder("setups") }));
    let stopping = crate::automation::shutdown_signal(app);
    tauri::async_runtime::spawn(async move { watcher.run(stopping).await });
    // Run on an event: each job's own address, and the folders that run jobs when they change.
    let events = events::Events::new(service.clone(), app.state::<jobs::Jobs>().inner().clone(), Some(Arc::new(events::EngineTunnels { app: app.clone() })), event_urls, true);
    app.manage(events.clone());
    let wired = service.clone();
    let opened = events.clone();
    tauri::async_runtime::spawn(async move { wired.wire_events(Arc::new(opened)).await });
    let stopping = crate::automation::shutdown_signal(app);
    tauri::async_runtime::spawn(async move { events.run(stopping).await });
    tauri::async_runtime::spawn(async move {
        service.reconcile_all().await;
        service.refresh_all().await;
    });
}
