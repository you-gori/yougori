//! Sessions in SQLite (`<state_dir>/sessions.db`): each session's messages in order, the
//! summaries compaction wrote, and how far old tool outputs are trimmed.
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: String,
    pub title: String,
    pub cwd: String,
    pub model: String,
    pub profile: String,
    pub created: i64,
    pub updated: i64,
    pub messages: i64,
}

/// One stored row: a message, or a summary compaction wrote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub seq: i64,
    pub kind: String,
    pub data: String,
}

pub const MESSAGE: &str = "message";
pub const SUMMARY: &str = "summary";

pub struct Store {
    conn: Mutex<Connection>,
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    cwd TEXT NOT NULL,
    model TEXT NOT NULL,
    profile TEXT NOT NULL,
    created INTEGER NOT NULL,
    updated INTEGER NOT NULL,
    trim_before INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS messages (
    session TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    seq INTEGER NOT NULL,
    kind TEXT NOT NULL,
    data TEXT NOT NULL,
    created INTEGER NOT NULL,
    PRIMARY KEY (session, seq)
);
CREATE INDEX IF NOT EXISTS sessions_by_folder ON sessions(cwd, updated);
";

fn now() -> i64 {
    super::util::unix_now() as i64
}

impl Store {
    pub fn open(path: &Path) -> Result<Store, String> {
        let conn = Connection::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5)).map_err(|e| e.to_string())?;
        // WAL keeps reads and writes from blocking each other; NORMAL sync is safe with WAL.
        conn.pragma_update(None, "journal_mode", "WAL").map_err(|e| e.to_string())?;
        conn.pragma_update(None, "synchronous", "NORMAL").map_err(|e| e.to_string())?;
        conn.pragma_update(None, "foreign_keys", "ON").map_err(|e| e.to_string())?;
        conn.execute_batch(SCHEMA).map_err(|e| format!("cannot prepare {}: {e}", path.display()))?;
        conn.pragma_update(None, "user_version", 1).map_err(|e| e.to_string())?;
        Ok(Store { conn: Mutex::new(conn) })
    }

    fn conn(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn create(&self, id: &str, title: &str, cwd: &str, model: &str, profile: &str) -> Result<(), String> {
        let time = now();
        self.conn()
            .execute(
                "INSERT INTO sessions (id, title, cwd, model, profile, created, updated) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)",
                params![id, title, cwd, model, profile, time],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Adds a row. A seq the session holds already is refused, never replaced: rows are only
    /// ever added, so a reused one would mean overwriting history.
    pub fn append(&self, session: &str, seq: i64, kind: &str, data: &str) -> Result<(), String> {
        let mut conn = self.conn();
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        let time = now();
        tx.execute(
            "INSERT INTO messages (session, seq, kind, data, created) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![session, seq, kind, data, time],
        )
        .map_err(|e| e.to_string())?;
        tx.execute("UPDATE sessions SET updated = ?2 WHERE id = ?1", params![session, time]).map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }

    /// Records the model and mode a session's latest turn used.
    pub fn touch(&self, session: &str, model: &str, profile: &str) -> Result<(), String> {
        self.conn()
            .execute(
                "UPDATE sessions SET model = ?2, profile = ?3, updated = ?4 WHERE id = ?1",
                params![session, model, profile, now()],
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    pub fn set_trim(&self, session: &str, trim_before: i64) -> Result<(), String> {
        self.conn()
            .execute("UPDATE sessions SET trim_before = ?2 WHERE id = ?1", params![session, trim_before])
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// The newest sessions started in `cwd`.
    pub fn sessions(&self, cwd: &str, limit: usize) -> Result<Vec<SessionInfo>, String> {
        let conn = self.conn();
        let mut statement = conn
            .prepare(
                "SELECT s.id, s.title, s.cwd, s.model, s.profile, s.created, s.updated,
                        (SELECT COUNT(*) FROM messages m WHERE m.session = s.id AND m.kind = 'message')
                 FROM sessions s WHERE s.cwd = ?1 ORDER BY s.updated DESC, s.created DESC LIMIT ?2",
            )
            .map_err(|e| e.to_string())?;
        let rows = statement
            .query_map(params![cwd, limit as i64], |row| {
                Ok(SessionInfo {
                    id: row.get(0)?,
                    title: row.get(1)?,
                    cwd: row.get(2)?,
                    model: row.get(3)?,
                    profile: row.get(4)?,
                    created: row.get(5)?,
                    updated: row.get(6)?,
                    messages: row.get(7)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>().map_err(|e| e.to_string())
    }

    /// A session, how far its outputs are trimmed, and its rows in order.
    pub fn load(&self, session: &str) -> Result<Option<(SessionInfo, i64, Vec<Row>)>, String> {
        let conn = self.conn();
        let found = conn
            .query_row(
                "SELECT id, title, cwd, model, profile, created, updated, trim_before FROM sessions WHERE id = ?1",
                params![session],
                |row| {
                    Ok((
                        SessionInfo {
                            id: row.get(0)?,
                            title: row.get(1)?,
                            cwd: row.get(2)?,
                            model: row.get(3)?,
                            profile: row.get(4)?,
                            created: row.get(5)?,
                            updated: row.get(6)?,
                            messages: 0,
                        },
                        row.get::<_, i64>(7)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| e.to_string())?;
        let Some((mut info, trim_before)) = found else { return Ok(None) };
        let mut statement =
            conn.prepare("SELECT seq, kind, data FROM messages WHERE session = ?1 ORDER BY seq").map_err(|e| e.to_string())?;
        let rows = statement
            .query_map(params![session], |row| Ok(Row { seq: row.get(0)?, kind: row.get(1)?, data: row.get(2)? }))
            .map_err(|e| e.to_string())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())?;
        info.messages = rows.iter().filter(|r| r.kind == MESSAGE).count() as i64;
        Ok(Some((info, trim_before, rows)))
    }
}

/// Runs a store call on a blocking thread.
pub async fn with<T, F>(store: &Arc<Store>, call: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&Store) -> Result<T, String> + Send + 'static,
{
    let store = store.clone();
    tokio::task::spawn_blocking(move || call(&store)).await.map_err(|e| format!("the session store failed: {e}"))?
}

/// A short title from a session's first prompt.
pub fn title(prompt: &str) -> String {
    let line = prompt.lines().map(str::trim).find(|l| !l.is_empty()).unwrap_or("New session");
    let words: Vec<&str> = line.split_whitespace().collect();
    let mut title = String::new();
    for word in words {
        if title.chars().count() + word.chars().count() + 1 > 60 {
            if title.is_empty() {
                title = word.chars().take(59).collect::<String>() + "\u{2026}";
            } else {
                title.push('\u{2026}');
            }
            return title;
        }
        if !title.is_empty() {
            title.push(' ');
        }
        title.push_str(word);
    }
    title
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sessions_round_trip() {
        let folder = tempfile::tempdir().unwrap();
        let path = folder.path().join("sessions.db");
        let store = Store::open(&path).unwrap();
        store.create("s1", "Fix the login", "/w", "m", "yougori").unwrap();
        store.append("s1", 0, MESSAGE, "{\"role\":\"user\",\"text\":\"hi\"}").unwrap();
        store.append("s1", 1, MESSAGE, "{\"role\":\"assistant\",\"text\":\"hello\"}").unwrap();
        store.append("s1", 2, SUMMARY, "{\"head\":\"h\",\"keep_from\":1}").unwrap();
        store.set_trim("s1", 1).unwrap();
        store.touch("s1", "m2", "plan").unwrap();
        store.create("s2", "Other folder", "/x", "m", "yougori").unwrap();
        drop(store);
        let store = Store::open(&path).unwrap();
        let list = store.sessions("/w", 10).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!((list[0].title.as_str(), list[0].messages, list[0].model.as_str()), ("Fix the login", 2, "m2"));
        let (info, trim, rows) = store.load("s1").unwrap().unwrap();
        assert_eq!((info.profile.as_str(), trim, rows.len()), ("plan", 1, 3));
        assert_eq!(rows[2].kind, SUMMARY);
        assert!(store.load("missing").unwrap().is_none());
        // A seq already stored is refused and the stored row stays as it was.
        assert!(store.append("s1", 0, MESSAGE, "{\"role\":\"user\",\"text\":\"overwrite\"}").is_err());
        let (_, _, rows) = store.load("s1").unwrap().unwrap();
        assert!(rows[0].data.contains("\"hi\""), "{:?}", rows[0]);
    }

    #[test]
    fn titles_are_short_first_lines() {
        assert_eq!(title("\n  Fix the login bug\nmore detail"), "Fix the login bug");
        let long = title(&"word ".repeat(40));
        assert!(long.chars().count() <= 61 && long.ends_with('\u{2026}'), "{long}");
        assert_eq!(title(""), "New session");
    }
}
