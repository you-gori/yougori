//! The progress port over P08's publisher ([`crate::model_memory::progress`], GPU §3.10
//! line 650).
//!
//! The publisher folds extent reports into one CORE-06 progress update per operation and
//! emits it on the event hub (T10). Both are shared with the rest of the engine, which
//! tracks each job's operation before submitting it, moves its stages and flushes held
//! updates; the adapter only reports extents. It locks the publisher, then the hub.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use super::ports::ProgressPort;
use crate::foundation::events::EventHub;
use crate::foundation::ids::{Clock, OperationId};
use crate::model_memory::progress::{ProgressPublisher, PublishError};

/// [`ProgressPort`] over a shared [`ProgressPublisher`] and the [`EventHub`] its
/// producer is registered on.
pub struct PublisherProgress<C, H> {
    publisher: Arc<Mutex<ProgressPublisher<C>>>,
    hub: Arc<Mutex<EventHub<H>>>,
}

impl<C, H> PublisherProgress<C, H> {
    /// Reports through `publisher`, emitting on `hub`.
    pub fn new(publisher: Arc<Mutex<ProgressPublisher<C>>>, hub: Arc<Mutex<EventHub<H>>>) -> Self {
        Self { publisher, hub }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl<C: Clock + Clone, H: Clock> ProgressPort for PublisherProgress<C, H> {
    fn extent_started(
        &mut self,
        operation: &OperationId,
        index: u64,
        length_bytes: u64,
    ) -> Result<(), PublishError> {
        let mut publisher = lock(&self.publisher);
        let mut hub = lock(&self.hub);
        publisher
            .extent_started(&mut hub, operation, index, length_bytes)
            .map(drop)
    }

    fn extent_arrived(
        &mut self,
        operation: &OperationId,
        index: u64,
        length_bytes: u64,
    ) -> Result<(), PublishError> {
        let mut publisher = lock(&self.publisher);
        let mut hub = lock(&self.hub);
        publisher
            .extent_arrived(&mut hub, operation, index, length_bytes)
            .map(drop)
    }

    fn extent_committed(
        &mut self,
        operation: &OperationId,
        index: u64,
    ) -> Result<(), PublishError> {
        let mut publisher = lock(&self.publisher);
        let mut hub = lock(&self.hub);
        publisher
            .extent_committed(&mut hub, operation, index)
            .map(drop)
    }

    fn extent_discarded(
        &mut self,
        operation: &OperationId,
        index: u64,
    ) -> Result<(), PublishError> {
        let mut publisher = lock(&self.publisher);
        let mut hub = lock(&self.hub);
        publisher
            .extent_discarded(&mut hub, operation, index)
            .map(drop)
    }
}
