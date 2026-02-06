use crate::agent_cx::AgentCx;
use crate::error::{Error, Result};
use crate::session::{SessionEntry, SessionHeader};
use asupersync::Outcome;
use asupersync::database::{SqliteConnection, SqliteError, SqliteRow, SqliteValue};
use std::path::Path;

const INIT_SQL: &str = r"
PRAGMA journal_mode = DELETE;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS pi_session_header (
  id TEXT PRIMARY KEY,
  json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pi_session_entries (
  seq INTEGER PRIMARY KEY,
  json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS pi_session_meta (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
";

#[derive(Debug, Clone)]
pub struct SqliteSessionMeta {
    pub header: SessionHeader,
    pub message_count: u64,
    pub name: Option<String>,
}

fn map_outcome<T>(outcome: Outcome<T, SqliteError>) -> Result<T> {
    match outcome {
        Outcome::Ok(value) => Ok(value),
        Outcome::Err(err) => Err(Error::session(format!("SQLite session error: {err}"))),
        Outcome::Cancelled(_) => Err(Error::Aborted),
        Outcome::Panicked(payload) => Err(Error::session(format!(
            "SQLite session operation panicked: {payload:?}"
        ))),
    }
}

fn row_get_str<'a>(row: &'a SqliteRow, column: &str) -> Result<&'a str> {
    row.get_str(column)
        .map_err(|err| Error::session(format!("SQLite row read failed: {err}")))
}

fn compute_message_count_and_name(entries: &[SessionEntry]) -> (u64, Option<String>) {
    let mut message_count = 0u64;
    let mut name = None;

    for entry in entries {
        match entry {
            SessionEntry::Message(_) => message_count += 1,
            SessionEntry::SessionInfo(info) => {
                if info.name.is_some() {
                    name.clone_from(&info.name);
                }
            }
            _ => {}
        }
    }

    (message_count, name)
}

pub async fn load_session(path: &Path) -> Result<(SessionHeader, Vec<SessionEntry>)> {
    if !path.exists() {
        return Err(Error::SessionNotFound {
            path: path.display().to_string(),
        });
    }

    let cx = AgentCx::for_request();
    let conn = map_outcome(SqliteConnection::open(cx.cx(), path).await)?;

    let header_rows = map_outcome(
        conn.query(cx.cx(), "SELECT json FROM pi_session_header LIMIT 1", &[])
            .await,
    )?;
    let header_row = header_rows
        .first()
        .ok_or_else(|| Error::session("SQLite session missing header row"))?;
    let header_json = row_get_str(header_row, "json")?;
    let header: SessionHeader = serde_json::from_str(header_json)?;

    let entry_rows = map_outcome(
        conn.query(
            cx.cx(),
            "SELECT json FROM pi_session_entries ORDER BY seq ASC",
            &[],
        )
        .await,
    )?;

    let mut entries = Vec::with_capacity(entry_rows.len());
    for row in entry_rows {
        let json = row_get_str(&row, "json")?;
        let entry: SessionEntry = serde_json::from_str(json)?;
        entries.push(entry);
    }

    Ok((header, entries))
}

pub async fn load_session_meta(path: &Path) -> Result<SqliteSessionMeta> {
    if !path.exists() {
        return Err(Error::SessionNotFound {
            path: path.display().to_string(),
        });
    }

    let cx = AgentCx::for_request();
    let conn = map_outcome(SqliteConnection::open(cx.cx(), path).await)?;

    let header_rows = map_outcome(
        conn.query(cx.cx(), "SELECT json FROM pi_session_header LIMIT 1", &[])
            .await,
    )?;
    let header_row = header_rows
        .first()
        .ok_or_else(|| Error::session("SQLite session missing header row"))?;
    let header_json = row_get_str(header_row, "json")?;
    let header: SessionHeader = serde_json::from_str(header_json)?;

    let meta_rows = map_outcome(
        conn.query(
            cx.cx(),
            "SELECT key,value FROM pi_session_meta WHERE key IN ('message_count','name')",
            &[],
        )
        .await,
    )?;

    let mut message_count: Option<u64> = None;
    let mut name: Option<String> = None;
    for row in meta_rows {
        let key = row_get_str(&row, "key")?;
        let value = row_get_str(&row, "value")?;
        match key {
            "message_count" => message_count = value.parse::<u64>().ok(),
            "name" => name = Some(value.to_string()),
            _ => {}
        }
    }

    let message_count = if let Some(message_count) = message_count {
        message_count
    } else {
        let entry_rows = map_outcome(
            conn.query(
                cx.cx(),
                "SELECT json FROM pi_session_entries ORDER BY seq ASC",
                &[],
            )
            .await,
        )?;

        let mut entries = Vec::with_capacity(entry_rows.len());
        for row in entry_rows {
            let json = row_get_str(&row, "json")?;
            let entry: SessionEntry = serde_json::from_str(json)?;
            entries.push(entry);
        }

        let (message_count, fallback_name) = compute_message_count_and_name(&entries);
        if name.is_none() {
            name = fallback_name;
        }
        message_count
    };
    Ok(SqliteSessionMeta {
        header,
        message_count,
        name,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::UserContent;
    use crate::session::{EntryBase, MessageEntry, SessionInfoEntry, SessionMessage};

    fn dummy_base() -> EntryBase {
        EntryBase {
            id: Some("test-id".to_string()),
            parent_id: None,
            timestamp: "2026-01-01T00:00:00.000Z".to_string(),
        }
    }

    fn message_entry() -> SessionEntry {
        SessionEntry::Message(MessageEntry {
            base: dummy_base(),
            message: SessionMessage::User {
                content: UserContent::Text("hello".to_string()),
                timestamp: None,
            },
        })
    }

    fn session_info_entry(name: Option<String>) -> SessionEntry {
        SessionEntry::SessionInfo(SessionInfoEntry {
            base: dummy_base(),
            name,
        })
    }

    #[test]
    fn compute_counts_empty() {
        let (count, name) = compute_message_count_and_name(&[]);
        assert_eq!(count, 0);
        assert!(name.is_none());
    }

    #[test]
    fn compute_counts_messages_only() {
        let entries = vec![message_entry(), message_entry(), message_entry()];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 3);
        assert!(name.is_none());
    }

    #[test]
    fn compute_counts_session_info_with_name() {
        let entries = vec![
            message_entry(),
            session_info_entry(Some("My Session".to_string())),
            message_entry(),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 2);
        assert_eq!(name, Some("My Session".to_string()));
    }

    #[test]
    fn compute_counts_session_info_none_name_ignored() {
        let entries = vec![
            session_info_entry(Some("First".to_string())),
            session_info_entry(None),
            message_entry(),
        ];
        let (count, name) = compute_message_count_and_name(&entries);
        assert_eq!(count, 1);
        // The second SessionInfo has name=None, so it doesn't overwrite.
        assert_eq!(name, Some("First".to_string()));
    }

    #[test]
    fn compute_counts_latest_name_wins() {
        let entries = vec![
            session_info_entry(Some("First".to_string())),
            session_info_entry(Some("Second".to_string())),
        ];
        let (_, name) = compute_message_count_and_name(&entries);
        assert_eq!(name, Some("Second".to_string()));
    }
}

pub async fn save_session(
    path: &Path,
    header: &SessionHeader,
    entries: &[SessionEntry],
) -> Result<()> {
    if let Some(parent) = path.parent() {
        asupersync::fs::create_dir_all(parent).await?;
    }

    let cx = AgentCx::for_request();
    let conn = map_outcome(SqliteConnection::open(cx.cx(), path).await)?;
    map_outcome(conn.execute_batch(cx.cx(), INIT_SQL).await)?;

    let tx = map_outcome(conn.begin_immediate(cx.cx()).await)?;

    map_outcome(
        tx.execute(cx.cx(), "DELETE FROM pi_session_entries", &[])
            .await,
    )?;
    map_outcome(
        tx.execute(cx.cx(), "DELETE FROM pi_session_header", &[])
            .await,
    )?;
    map_outcome(
        tx.execute(cx.cx(), "DELETE FROM pi_session_meta", &[])
            .await,
    )?;

    let header_json = serde_json::to_string(header)?;
    map_outcome(
        tx.execute(
            cx.cx(),
            "INSERT INTO pi_session_header (id,json) VALUES (?1,?2)",
            &[
                SqliteValue::Text(header.id.clone()),
                SqliteValue::Text(header_json),
            ],
        )
        .await,
    )?;

    for (idx, entry) in entries.iter().enumerate() {
        let json = serde_json::to_string(entry)?;
        map_outcome(
            tx.execute(
                cx.cx(),
                "INSERT INTO pi_session_entries (seq,json) VALUES (?1,?2)",
                &[
                    SqliteValue::Integer(i64::try_from(idx + 1).unwrap_or(i64::MAX)),
                    SqliteValue::Text(json),
                ],
            )
            .await,
        )?;
    }

    let (message_count, name) = compute_message_count_and_name(entries);
    map_outcome(
        tx.execute(
            cx.cx(),
            "INSERT INTO pi_session_meta (key,value) VALUES (?1,?2)",
            &[
                SqliteValue::Text("message_count".to_string()),
                SqliteValue::Text(message_count.to_string()),
            ],
        )
        .await,
    )?;
    if let Some(name) = name {
        map_outcome(
            tx.execute(
                cx.cx(),
                "INSERT INTO pi_session_meta (key,value) VALUES (?1,?2)",
                &[
                    SqliteValue::Text("name".to_string()),
                    SqliteValue::Text(name),
                ],
            )
            .await,
        )?;
    }

    map_outcome(tx.commit(cx.cx()).await)?;
    Ok(())
}
