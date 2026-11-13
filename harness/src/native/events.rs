//! Talking to the screen: sending events, and waiting for the person's answers to permission
//! requests and questions (the engine's command loop routes each answer here by its id).
use super::cancel::Cancel;
use super::permissions::{judge, Action, Rule, Subject, Vars};
use crate::protocol::{Event, Level, PermissionRequest, QuestionRequest};
use std::collections::HashMap;
use std::sync::Mutex;
use tokio::sync::{mpsc, oneshot};

#[derive(Clone)]
pub struct Events(mpsc::UnboundedSender<Event>);

impl Events {
    pub fn new(sender: mpsc::UnboundedSender<Event>) -> Events {
        Events(sender)
    }

    /// Sends an event; a screen that has gone away is not an error here.
    pub fn send(&self, event: Event) {
        let _ = self.0.send(event);
    }

    pub fn notice(&self, level: Level, text: impl Into<String>) {
        self.send(Event::Notice { level, text: text.into() });
    }
}

/// The person stopped the turn while the engine waited for them.
#[derive(Debug, PartialEq, Eq)]
pub struct Stopped;

struct Waiting {
    answer: oneshot::Sender<Option<String>>,
    /// What the request is about, to answer it from rules added later.
    subjects: Vec<Subject>,
    rules: Vec<Rule>,
}

#[derive(Default)]
pub struct Broker {
    permissions: Mutex<HashMap<String, Waiting>>,
    questions: Mutex<HashMap<String, oneshot::Sender<Option<Vec<String>>>>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

/// Takes a request out of its map when the wait ends, however it ends.
struct Forget<'a, T> {
    map: &'a Mutex<HashMap<String, T>>,
    id: String,
}

impl<T> Drop for Forget<'_, T> {
    fn drop(&mut self) {
        lock(self.map).remove(&self.id);
    }
}

impl Broker {
    /// Asks the person; the chosen option id, None when they dismissed it.
    pub async fn permission(
        &self,
        events: &Events,
        request: PermissionRequest,
        subjects: Vec<Subject>,
        rules: Vec<Rule>,
        cancel: &Cancel,
    ) -> Result<Option<String>, Stopped> {
        let (sender, receiver) = oneshot::channel();
        let id = request.id.clone();
        lock(&self.permissions).insert(id.clone(), Waiting { answer: sender, subjects, rules });
        let _forget = Forget { map: &self.permissions, id };
        events.send(Event::Permission(request));
        tokio::select! {
            answer = receiver => Ok(answer.unwrap_or(None)),
            _ = cancel.cancelled() => Err(Stopped),
        }
    }

    /// The person's answer; false when nothing waits for it.
    pub fn answer_permission(&self, id: &str, option: Option<String>) -> bool {
        match lock(&self.permissions).remove(id) {
            Some(waiting) => waiting.answer.send(option).is_ok(),
            None => false,
        }
    }

    /// After an "always" answer: answers the waiting requests the session's rules now settle.
    pub fn settle(&self, session: &[Rule], vars: &Vars) -> usize {
        let mut map = lock(&self.permissions);
        let settled: Vec<(String, &'static str)> = map
            .iter()
            .filter(|(_, w)| !w.subjects.is_empty())
            .filter_map(|(id, w)| match judge(&w.rules, session, &w.subjects, vars).action {
                Action::Allow => Some((id.clone(), "allow_once")),
                Action::Deny => Some((id.clone(), "reject_once")),
                Action::Ask => None,
            })
            .collect();
        for (id, option) in &settled {
            if let Some(waiting) = map.remove(id) {
                let _ = waiting.answer.send(Some((*option).to_owned()));
            }
        }
        settled.len()
    }

    /// Asks the person a question; their answers, None when they dismissed it.
    pub async fn question(&self, events: &Events, request: QuestionRequest, cancel: &Cancel) -> Result<Option<Vec<String>>, Stopped> {
        let (sender, receiver) = oneshot::channel();
        let id = request.id.clone();
        lock(&self.questions).insert(id.clone(), sender);
        let _forget = Forget { map: &self.questions, id };
        events.send(Event::Question(request));
        tokio::select! {
            answer = receiver => Ok(answer.unwrap_or(None)),
            _ = cancel.cancelled() => Err(Stopped),
        }
    }

    pub fn answer_question(&self, id: &str, answer: Option<Vec<String>>) -> bool {
        match lock(&self.questions).remove(id) {
            Some(sender) => sender.send(answer).is_ok(),
            None => false,
        }
    }

    #[cfg(test)]
    pub fn waiting(&self) -> usize {
        lock(&self.permissions).len() + lock(&self.questions).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native::permissions::bash_subjects;
    use crate::protocol::PermissionRequest;
    use std::sync::Arc;
    use std::time::Duration;

    fn request(id: &str) -> PermissionRequest {
        PermissionRequest { id: id.into(), title: "Run".into(), ..Default::default() }
    }

    #[tokio::test]
    async fn answers_reach_the_waiting_request_and_always_rules_settle_others() {
        let broker = Arc::new(Broker::default());
        let (sender, mut screen) = mpsc::unbounded_channel();
        let events = Events::new(sender);
        let rules = vec![Rule { tool: "bash".into(), pattern: "*".into(), action: Action::Ask }];
        let cancel = Cancel::new();
        let first = {
            let (broker, events, rules, cancel) = (broker.clone(), events.clone(), rules.clone(), cancel.clone());
            tokio::spawn(async move { broker.permission(&events, request("p1"), bash_subjects("cargo test"), rules, &cancel).await })
        };
        let second = {
            let (broker, events, rules, cancel) = (broker.clone(), events.clone(), rules.clone(), cancel.clone());
            tokio::spawn(async move { broker.permission(&events, request("p2"), bash_subjects("cargo test --all"), rules, &cancel).await })
        };
        for _ in 0..2 {
            assert!(matches!(screen.recv().await, Some(Event::Permission(_))));
        }
        assert!(broker.answer_permission("p1", Some("allow_always".into())));
        assert_eq!(first.await.unwrap(), Ok(Some("allow_always".into())));
        let session = vec![Rule { tool: "bash".into(), pattern: "cargo test*".into(), action: Action::Allow }];
        assert_eq!(broker.settle(&session, &Vars::default()), 1);
        assert_eq!(second.await.unwrap(), Ok(Some("allow_once".into())));
        assert!(!broker.answer_permission("p2", None), "already answered");
        assert_eq!(broker.waiting(), 0);
    }

    #[tokio::test]
    async fn a_cancel_ends_the_wait_and_forgets_the_request() {
        let broker = Broker::default();
        let (sender, _screen) = mpsc::unbounded_channel();
        let events = Events::new(sender);
        let cancel = Cancel::new();
        let trigger = cancel.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(30)).await;
            trigger.cancel();
        });
        let request = QuestionRequest { id: "q".into(), question: "Which?".into(), ..Default::default() };
        assert_eq!(broker.question(&events, request, &cancel).await, Err(Stopped));
        assert_eq!(broker.waiting(), 0);
        assert!(!broker.answer_question("q", Some(vec!["a".into()])));
    }
}
