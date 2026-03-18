use crate::alerting::AlertEvent;
use log::{info, warn};
use rusqlite::{params, Connection};
use std::sync::Mutex;

/// SQLite-backed event store for the dashboard.
/// Uses std::sync::Mutex because rusqlite::Connection is !Send
/// and all operations are fast (sub-millisecond for single rows).
pub struct EventDb {
    conn: Mutex<Connection>,
}

/// Filter parameters for querying stored events.
#[derive(Debug, Default, serde::Deserialize)]
pub struct EventFilter {
    pub severity: Option<String>,
    pub action: Option<String>,
    pub agent_name: Option<String>,
    pub event_type: Option<String>,
    pub path_contains: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

/// A single event row from the database.
#[derive(Debug, serde::Serialize)]
pub struct StoredEvent {
    pub id: i64,
    pub timestamp: String,
    pub severity: String,
    pub event_type: String,
    pub action: String,
    pub agent_name: String,
    pub pid: u32,
    pub comm: String,
    pub path: String,
    pub access_mode: String,
    pub identity_method: String,
    pub policy_mode: String,
}

/// A resolved permission from the audit trail.
#[derive(Debug, serde::Serialize)]
pub struct StoredPermissionAudit {
    pub id: i64,
    pub request_id: i64,
    pub agent_name: String,
    pub resource_type: String,
    pub resource_path: String,
    pub justification: Option<String>,
    pub risk_level: Option<String>,
    pub risk_flags: Option<String>,
    pub requested_at: String,
    pub resolved_at: String,
    pub approved: bool,
    pub reason: String,
    pub grant_duration_secs: Option<i64>,
}

impl EventDb {
    /// Open (or create) the SQLite database at the given path.
    pub fn open(path: &str) -> Result<Self, String> {
        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("Failed to create DB directory {:?}: {}", parent, e))?;
            }
        }

        let conn = Connection::open(path)
            .map_err(|e| format!("Failed to open SQLite DB at {}: {}", path, e))?;

        // WAL mode for better concurrent read/write performance
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA busy_timeout=5000;")
            .map_err(|e| format!("Failed to set PRAGMA: {}", e))?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                action TEXT NOT NULL,
                agent_name TEXT NOT NULL,
                pid INTEGER NOT NULL,
                comm TEXT NOT NULL,
                path TEXT NOT NULL,
                access_mode TEXT NOT NULL DEFAULT '',
                identity_method TEXT NOT NULL DEFAULT '',
                policy_mode TEXT NOT NULL DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_events_severity ON events(severity);
            CREATE INDEX IF NOT EXISTS idx_events_agent ON events(agent_name);
            CREATE INDEX IF NOT EXISTS idx_events_action ON events(action);

            CREATE TABLE IF NOT EXISTS permission_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                request_id INTEGER NOT NULL,
                agent_name TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_path TEXT NOT NULL,
                justification TEXT,
                risk_level TEXT,
                risk_flags TEXT,
                requested_at TEXT NOT NULL,
                resolved_at TEXT NOT NULL,
                approved INTEGER NOT NULL,
                reason TEXT NOT NULL,
                grant_duration_secs INTEGER
            );
            CREATE INDEX IF NOT EXISTS idx_perm_audit_agent ON permission_audit(agent_name);
            CREATE INDEX IF NOT EXISTS idx_perm_audit_resolved ON permission_audit(resolved_at DESC);
            CREATE INDEX IF NOT EXISTS idx_perm_audit_approved ON permission_audit(approved);",
        )
        .map_err(|e| format!("Failed to create tables: {}", e))?;

        info!("Event database opened: {}", path);

        Ok(EventDb {
            conn: Mutex::new(conn),
        })
    }

    /// Insert an AlertEvent into the database.
    pub fn insert_event(&self, event: &AlertEvent) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        conn.execute(
            "INSERT INTO events (timestamp, severity, event_type, action, agent_name, pid, comm, path, access_mode, identity_method, policy_mode)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                event.timestamp.to_rfc3339(),
                event.severity.to_string(),
                event.event_type.to_string(),
                event.action.to_string(),
                event.agent_name,
                event.pid,
                event.comm,
                event.path,
                event.access_mode,
                event.identity_method,
                event.policy_mode,
            ],
        )
        .map_err(|e| format!("DB insert failed: {}", e))?;
        Ok(())
    }

    /// Query events with optional filters, pagination via limit/offset.
    pub fn query_events(&self, filter: &EventFilter) -> Result<Vec<StoredEvent>, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;

        let (where_clause, bind_values) = build_where_clause(filter);
        let limit = filter.limit.unwrap_or(100).min(1000);
        let offset = filter.offset.unwrap_or(0);

        let sql = format!(
            "SELECT id, timestamp, severity, event_type, action, agent_name, pid, comm, path, access_mode, identity_method, policy_mode
             FROM events {} ORDER BY id DESC LIMIT {} OFFSET {}",
            where_clause, limit, offset
        );

        let mut stmt = conn.prepare(&sql).map_err(|e| format!("Query prepare failed: {}", e))?;

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            bind_values.iter().map(|v| v as &dyn rusqlite::types::ToSql).collect();

        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                Ok(StoredEvent {
                    id: row.get(0)?,
                    timestamp: row.get(1)?,
                    severity: row.get(2)?,
                    event_type: row.get(3)?,
                    action: row.get(4)?,
                    agent_name: row.get(5)?,
                    pid: row.get(6)?,
                    comm: row.get(7)?,
                    path: row.get(8)?,
                    access_mode: row.get(9)?,
                    identity_method: row.get(10)?,
                    policy_mode: row.get(11)?,
                })
            })
            .map_err(|e| format!("Query failed: {}", e))?;

        let mut events = Vec::new();
        for row in rows {
            match row {
                Ok(ev) => events.push(ev),
                Err(e) => warn!("Skipping malformed DB row: {}", e),
            }
        }
        Ok(events)
    }

    /// Count events matching the filter (for pagination).
    pub fn count_events(&self, filter: &EventFilter) -> Result<u64, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        let (where_clause, bind_values) = build_where_clause(filter);
        let sql = format!("SELECT COUNT(*) FROM events {}", where_clause);

        let params_refs: Vec<&dyn rusqlite::types::ToSql> =
            bind_values.iter().map(|v| v as &dyn rusqlite::types::ToSql).collect();

        let count: u64 = conn
            .query_row(&sql, params_refs.as_slice(), |row| row.get(0))
            .map_err(|e| format!("Count query failed: {}", e))?;
        Ok(count)
    }

    /// Insert a resolved permission into the audit trail.
    pub fn insert_permission_audit(
        &self,
        request_id: u64,
        agent_name: &str,
        resource_type: &str,
        resource_path: &str,
        justification: Option<&str>,
        risk_level: &str,
        risk_flags: &[String],
        requested_at: &str,
        resolved_at: &str,
        approved: bool,
        reason: &str,
        grant_duration_secs: Option<u64>,
    ) -> Result<(), String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        let risk_flags_json = serde_json::to_string(risk_flags).unwrap_or_default();
        conn.execute(
            "INSERT INTO permission_audit (request_id, agent_name, resource_type, resource_path, justification, risk_level, risk_flags, requested_at, resolved_at, approved, reason, grant_duration_secs)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                request_id as i64,
                agent_name,
                resource_type,
                resource_path,
                justification,
                risk_level,
                risk_flags_json,
                requested_at,
                resolved_at,
                approved as i32,
                reason,
                grant_duration_secs.map(|d| d as i64),
            ],
        )
        .map_err(|e| format!("Permission audit insert failed: {}", e))?;
        Ok(())
    }

    /// Query recent permission audit entries.
    pub fn query_permission_audit(&self, limit: u32) -> Result<Vec<StoredPermissionAudit>, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        let mut stmt = conn
            .prepare(
                "SELECT id, request_id, agent_name, resource_type, resource_path, justification, risk_level, risk_flags, requested_at, resolved_at, approved, reason, grant_duration_secs
                 FROM permission_audit ORDER BY id DESC LIMIT ?1",
            )
            .map_err(|e| format!("Query prepare failed: {}", e))?;

        let rows = stmt
            .query_map(params![limit], |row| {
                Ok(StoredPermissionAudit {
                    id: row.get(0)?,
                    request_id: row.get(1)?,
                    agent_name: row.get(2)?,
                    resource_type: row.get(3)?,
                    resource_path: row.get(4)?,
                    justification: row.get(5)?,
                    risk_level: row.get(6)?,
                    risk_flags: row.get(7)?,
                    requested_at: row.get(8)?,
                    resolved_at: row.get(9)?,
                    approved: row.get::<_, i32>(10)? != 0,
                    reason: row.get(11)?,
                    grant_duration_secs: row.get(12)?,
                })
            })
            .map_err(|e| format!("Query failed: {}", e))?;

        let mut entries = Vec::new();
        for row in rows {
            match row {
                Ok(entry) => entries.push(entry),
                Err(e) => warn!("Skipping malformed permission audit row: {}", e),
            }
        }
        Ok(entries)
    }

    // =========================================================================
    // Anomaly Detection Queries (Phase 8d)
    // =========================================================================

    /// Get approval rate in the last 24 hours: (total, approved).
    pub fn approval_rate_24h(&self) -> Result<(u64, u64), String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
        let total: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM permission_audit WHERE resolved_at > ?1",
                params![cutoff],
                |row| row.get(0),
            )
            .map_err(|e| format!("Query failed: {}", e))?;
        let approved: u64 = conn
            .query_row(
                "SELECT COUNT(*) FROM permission_audit WHERE resolved_at > ?1 AND approved = 1",
                params![cutoff],
                |row| row.get(0),
            )
            .map_err(|e| format!("Query failed: {}", e))?;
        Ok((total, approved))
    }

    /// Get agents with more than `threshold` permission requests in the last 24h.
    pub fn high_volume_agents_24h(&self, threshold: u64) -> Result<Vec<(String, u64)>, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
        let mut stmt = conn
            .prepare(
                "SELECT agent_name, COUNT(*) as cnt FROM permission_audit
                 WHERE resolved_at > ?1 GROUP BY agent_name HAVING cnt > ?2",
            )
            .map_err(|e| format!("Query prepare failed: {}", e))?;
        let rows = stmt
            .query_map(params![cutoff, threshold as i64], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, u64>(1)?))
            })
            .map_err(|e| format!("Query failed: {}", e))?;
        let mut results = Vec::new();
        for row in rows {
            if let Ok(r) = row {
                results.push(r);
            }
        }
        Ok(results)
    }

    /// Find agents that had a deny followed by an approve for the same resource
    /// within the last 24h (persistence/retry attack pattern).
    pub fn agents_with_deny_then_approve(&self) -> Result<Vec<String>, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        let cutoff = (chrono::Utc::now() - chrono::Duration::hours(24)).to_rfc3339();
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT d.agent_name FROM permission_audit d
                 INNER JOIN permission_audit a
                   ON d.agent_name = a.agent_name
                   AND d.resource_path = a.resource_path
                   AND d.approved = 0 AND a.approved = 1
                   AND a.resolved_at > d.resolved_at
                 WHERE d.resolved_at > ?1",
            )
            .map_err(|e| format!("Query prepare failed: {}", e))?;
        let rows = stmt
            .query_map(params![cutoff], |row| row.get::<_, String>(0))
            .map_err(|e| format!("Query failed: {}", e))?;
        let mut results = Vec::new();
        for row in rows {
            if let Ok(name) = row {
                results.push(name);
            }
        }
        Ok(results)
    }

    /// Delete events older than the given number of days.
    pub fn prune_old_events(&self, max_age_days: u32) -> Result<u64, String> {
        let conn = self.conn.lock().map_err(|e| format!("DB lock poisoned: {}", e))?;
        let cutoff = chrono::Utc::now() - chrono::Duration::days(max_age_days as i64);
        let deleted = conn
            .execute(
                "DELETE FROM events WHERE timestamp < ?1",
                params![cutoff.to_rfc3339()],
            )
            .map_err(|e| format!("Prune failed: {}", e))?;
        Ok(deleted as u64)
    }
}

/// Build a WHERE clause and corresponding bind values from the filter.
fn build_where_clause(filter: &EventFilter) -> (String, Vec<String>) {
    let mut conditions: Vec<String> = Vec::new();
    let mut values: Vec<String> = Vec::new();

    if let Some(ref s) = filter.severity {
        if !s.is_empty() {
            values.push(s.clone());
            conditions.push(format!("severity = ?{}", values.len()));
        }
    }
    if let Some(ref a) = filter.action {
        if !a.is_empty() {
            values.push(a.clone());
            conditions.push(format!("action = ?{}", values.len()));
        }
    }
    if let Some(ref n) = filter.agent_name {
        if !n.is_empty() {
            values.push(n.clone());
            conditions.push(format!("agent_name = ?{}", values.len()));
        }
    }
    if let Some(ref t) = filter.event_type {
        if !t.is_empty() {
            values.push(t.clone());
            conditions.push(format!("event_type = ?{}", values.len()));
        }
    }
    if let Some(ref p) = filter.path_contains {
        if !p.is_empty() {
            values.push(format!("%{}%", p));
            conditions.push(format!("path LIKE ?{}", values.len()));
        }
    }

    let clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    (clause, values)
}
