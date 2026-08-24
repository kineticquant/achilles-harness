//! SQLite `achilles.db` access. Proprietary — `LICENSE-ACHILLES`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Row, Sqlite};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::types::{
    Assessment, AssessmentStatus, Engagement, Finding, HandleBlob, NewFinding,
};

pub const DB_NAME: &str = "achilles.db";
pub const ACHILLES_FOLDER: &str = "achilles";

#[derive(Clone)]
pub struct AchillesStore {
    pool: Pool<Sqlite>,
    initialized: Arc<OnceCell<()>>,
    root: PathBuf,
}

impl AchillesStore {
    pub fn new(data_dir: PathBuf) -> Self {
        let dir = data_dir.join(ACHILLES_FOLDER);
        let db_path = dir.join(DB_NAME);
        if let Some(parent) = db_path.parent() {
            std::fs::create_dir_all(parent).expect("create achilles data dir");
        }
        let _ = crate::seed::seed_bundled_review_checks(&data_dir);

        let options = SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true)
            .foreign_keys(true)
            .busy_timeout(std::time::Duration::from_secs(30))
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal);

        Self {
            pool: SqlitePoolOptions::new().connect_lazy_with(options),
            initialized: Arc::new(OnceCell::new()),
            root: dir,
        }
    }

    pub async fn pool(&self) -> Result<&Pool<Sqlite>> {
        self.initialized
            .get_or_try_init(|| async {
                Self::create_schema(&self.pool).await?;
                Ok::<(), anyhow::Error>(())
            })
            .await?;
        Ok(&self.pool)
    }

    async fn create_schema(pool: &Pool<Sqlite>) -> Result<()> {
        let mut tx = pool.begin_with("BEGIN IMMEDIATE").await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER PRIMARY KEY
            );
            "#,
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS engagements (
                id TEXT PRIMARY KEY,
                working_dir TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_assessment_at TEXT,
                status TEXT NOT NULL DEFAULT 'active'
            );
            "#,
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS assessments (
                id TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                session_id TEXT,
                mode TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                updated_at TEXT NOT NULL,
                parent_assessment_id TEXT,
                phases_json TEXT NOT NULL DEFAULT '{}',
                stats_json TEXT NOT NULL DEFAULT '{}',
                error_message TEXT,
                trigger TEXT NOT NULL DEFAULT 'scan_cta',
                FOREIGN KEY(engagement_id) REFERENCES engagements(id)
            );
            "#,
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                assessment_id TEXT NOT NULL,
                last_seen_assessment_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                state TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence TEXT NOT NULL,
                category TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT NOT NULL,
                path TEXT,
                line_start INTEGER,
                line_end INTEGER,
                cwe_json TEXT NOT NULL DEFAULT '[]',
                cve_json TEXT NOT NULL DEFAULT '[]',
                evidence_json TEXT NOT NULL DEFAULT '{}',
                first_seen_at TEXT NOT NULL,
                last_seen_at TEXT NOT NULL,
                UNIQUE(engagement_id, fingerprint)
            );
            "#,
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS engine_runs (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                engine TEXT NOT NULL,
                pack TEXT,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                exit_code INTEGER,
                summary_json TEXT,
                error_message TEXT
            );
            "#,
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_assessments_engagement ON assessments(engagement_id)",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_findings_assessment ON findings(last_seen_assessment_id)",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id)",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_engine_runs_assessment ON engine_runs(assessment_id)",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS handle_index (
                handle_id TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                path TEXT NOT NULL,
                bytes INTEGER NOT NULL,
                sha256 TEXT NOT NULL,
                created_at TEXT NOT NULL,
                assessment_id TEXT
            );
            "#,
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query("INSERT OR IGNORE INTO schema_version (version) VALUES (1)")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    pub async fn upsert_engagement(&self, working_dir: &str) -> Result<Engagement> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        let display_name = Path::new(working_dir)
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or(working_dir)
            .to_string();

        if let Some(existing) = sqlx::query(
            "SELECT id, working_dir, display_name, created_at, updated_at, last_assessment_at, status
             FROM engagements WHERE working_dir = ?",
        )
        .bind(working_dir)
        .fetch_optional(pool)
        .await?
        {
            return Ok(engagement_from_row(&existing));
        }

        let id = Uuid::new_v4().to_string();
        sqlx::query(
            "INSERT INTO engagements (id, working_dir, display_name, created_at, updated_at, status)
             VALUES (?, ?, ?, ?, ?, 'active')",
        )
        .bind(&id)
        .bind(working_dir)
        .bind(&display_name)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await?;

        Ok(Engagement {
            id,
            working_dir: working_dir.to_string(),
            display_name,
            created_at: now.clone(),
            updated_at: now,
            last_assessment_at: None,
            status: "active".into(),
        })
    }

    pub async fn create_assessment(
        &self,
        engagement: &Engagement,
        session_id: Option<&str>,
        mode: &str,
        trigger: &str,
        parent_assessment_id: Option<&str>,
    ) -> Result<Assessment> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        let id = Uuid::new_v4().to_string();
        let phases = serde_json::json!({
            "fingerprint": "queued",
            "secrets": "queued",
            "sca": "queued"
        });
        let stats = serde_json::json!({});
        sqlx::query(
            r#"
            INSERT INTO assessments (
                id, engagement_id, session_id, mode, status, started_at, updated_at,
                parent_assessment_id, phases_json, stats_json, trigger
            ) VALUES (?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(&engagement.id)
        .bind(session_id)
        .bind(mode)
        .bind(&now)
        .bind(&now)
        .bind(parent_assessment_id)
        .bind(phases.to_string())
        .bind(stats.to_string())
        .bind(trigger)
        .execute(pool)
        .await?;

        Ok(Assessment {
            id,
            engagement_id: engagement.id.clone(),
            working_dir: engagement.working_dir.clone(),
            session_id: session_id.map(str::to_string),
            mode: mode.to_string(),
            status: AssessmentStatus::Running,
            started_at: now.clone(),
            finished_at: None,
            updated_at: now,
            phases_json: phases,
            stats_json: stats,
            error_message: None,
            trigger: trigger.to_string(),
            parent_assessment_id: parent_assessment_id.map(str::to_string),
            open_finding_count: 0,
        })
    }

    pub async fn set_phase(&self, assessment_id: &str, phase: &str, status: &str) -> Result<()> {
        let pool = self.pool().await?;
        let row = sqlx::query("SELECT phases_json FROM assessments WHERE id = ?")
            .bind(assessment_id)
            .fetch_one(pool)
            .await?;
        let raw: String = row.get("phases_json");
        let mut phases: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or(serde_json::json!({}));
        if let Some(obj) = phases.as_object_mut() {
            obj.insert(
                phase.to_string(),
                serde_json::Value::String(status.to_string()),
            );
        }
        let now = now_rfc3339();
        sqlx::query("UPDATE assessments SET phases_json = ?, updated_at = ? WHERE id = ?")
            .bind(phases.to_string())
            .bind(now)
            .bind(assessment_id)
            .execute(pool)
            .await?;
        Ok(())
    }

    pub async fn finish_assessment(
        &self,
        assessment_id: &str,
        status: AssessmentStatus,
        stats: serde_json::Value,
        error_message: Option<&str>,
    ) -> Result<()> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        sqlx::query(
            r#"
            UPDATE assessments
            SET status = ?, finished_at = ?, updated_at = ?, stats_json = ?, error_message = ?
            WHERE id = ?
            "#,
        )
        .bind(status.as_str())
        .bind(&now)
        .bind(&now)
        .bind(stats.to_string())
        .bind(error_message)
        .bind(assessment_id)
        .execute(pool)
        .await?;

        sqlx::query(
            r#"
            UPDATE engagements
            SET last_assessment_at = ?, updated_at = ?
            WHERE id = (SELECT engagement_id FROM assessments WHERE id = ?)
            "#,
        )
        .bind(&now)
        .bind(&now)
        .bind(assessment_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn record_engine_run(
        &self,
        assessment_id: &str,
        engine: &str,
        status: &str,
        summary: serde_json::Value,
        error_message: Option<&str>,
    ) -> Result<()> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO engine_runs (
                id, assessment_id, engine, status, started_at, finished_at, summary_json, error_message
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(assessment_id)
        .bind(engine)
        .bind(status)
        .bind(&now)
        .bind(&now)
        .bind(summary.to_string())
        .bind(error_message)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn write_handle(
        &self,
        assessment_id: &str,
        kind: &str,
        payload: &serde_json::Value,
    ) -> Result<HandleBlob> {
        let _ = self.pool().await?;
        let handle_id = Uuid::new_v4().to_string();
        let dir = self.root.join("handles");
        std::fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{handle_id}.json"));
        let bytes = serde_json::to_vec_pretty(payload)?;
        std::fs::write(&path, &bytes)?;
        let mut hasher = Sha256::new();
        hasher.update(&bytes);
        let sha256 = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        let now = now_rfc3339();
        let pool = self.pool().await?;
        sqlx::query(
            r#"
            INSERT INTO handle_index (
                handle_id, kind, path, bytes, sha256, created_at, assessment_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&handle_id)
        .bind(kind)
        .bind(path.to_string_lossy().as_ref())
        .bind(bytes.len() as i64)
        .bind(&sha256)
        .bind(&now)
        .bind(assessment_id)
        .execute(pool)
        .await?;
        Ok(HandleBlob {
            handle_id,
            kind: kind.to_string(),
            bytes: bytes.len() as i64,
            sha256,
            preview: preview_from_payload(payload),
            payload: Some(payload.clone()),
        })
    }

    pub async fn get_handle(&self, handle_id: &str, include_payload: bool) -> Result<Option<HandleBlob>> {
        let pool = self.pool().await?;
        let row = sqlx::query(
            "SELECT handle_id, kind, path, bytes, sha256 FROM handle_index WHERE handle_id = ?",
        )
        .bind(handle_id)
        .fetch_optional(pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let path: String = row.get("path");
        let payload = std::fs::read_to_string(&path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok());
        let preview = payload
            .as_ref()
            .map(preview_from_payload)
            .unwrap_or_default();
        Ok(Some(HandleBlob {
            handle_id: row.get("handle_id"),
            kind: row.get("kind"),
            bytes: row.get("bytes"),
            sha256: row.get("sha256"),
            preview,
            payload: if include_payload { payload } else { None },
        }))
    }

    pub async fn upsert_finding(
        &self,
        engagement_id: &str,
        assessment_id: &str,
        finding: &NewFinding,
    ) -> Result<()> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        let id = Uuid::new_v4().to_string();
        let cwe = serde_json::to_string(&finding.cwe)?;
        let cve = serde_json::to_string(&finding.cve)?;
        let evidence = finding.evidence.to_string();
        sqlx::query(
            r#"
            INSERT INTO findings (
                id, engagement_id, assessment_id, last_seen_assessment_id, fingerprint,
                state, severity, confidence, category, rule_id, title, description,
                path, line_start, line_end, cwe_json, cve_json, evidence_json,
                first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(engagement_id, fingerprint) DO UPDATE SET
                last_seen_assessment_id = excluded.last_seen_assessment_id,
                last_seen_at = excluded.last_seen_at,
                severity = excluded.severity,
                title = excluded.title,
                description = excluded.description,
                evidence_json = excluded.evidence_json,
                cve_json = excluded.cve_json,
                state = CASE
                    WHEN findings.state = 'verified_fixed' THEN 'open'
                    ELSE findings.state
                END
            "#,
        )
        .bind(&id)
        .bind(engagement_id)
        .bind(assessment_id)
        .bind(assessment_id)
        .bind(&finding.fingerprint)
        .bind(finding.severity.as_str())
        .bind(&finding.confidence)
        .bind(&finding.category)
        .bind(&finding.rule_id)
        .bind(&finding.title)
        .bind(&finding.description)
        .bind(&finding.path)
        .bind(finding.line_start)
        .bind(finding.line_end)
        .bind(cwe)
        .bind(cve)
        .bind(evidence)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn get_assessment(&self, assessment_id: &str) -> Result<Option<Assessment>> {
        let pool = self.pool().await?;
        let row = sqlx::query(
            r#"
            SELECT a.*, e.working_dir,
                (SELECT COUNT(*) FROM findings f
                 WHERE f.last_seen_assessment_id = a.id AND f.state = 'open') AS open_finding_count
            FROM assessments a
            JOIN engagements e ON e.id = a.engagement_id
            WHERE a.id = ?
            "#,
        )
        .bind(assessment_id)
        .fetch_optional(pool)
        .await?;
        Ok(row.as_ref().map(assessment_from_row))
    }

    pub async fn list_assessments(&self, working_dir: Option<&str>) -> Result<Vec<Assessment>> {
        let pool = self.pool().await?;
        let rows = if let Some(dir) = working_dir {
            let dir = normalize_working_dir_for_query(dir);
            sqlx::query(
                r#"
                SELECT a.*, e.working_dir,
                    (SELECT COUNT(*) FROM findings f
                     WHERE f.last_seen_assessment_id = a.id AND f.state = 'open') AS open_finding_count
                FROM assessments a
                JOIN engagements e ON e.id = a.engagement_id
                WHERE e.working_dir = ?
                ORDER BY a.started_at DESC
                LIMIT 50
                "#,
            )
            .bind(dir)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query(
                r#"
                SELECT a.*, e.working_dir,
                    (SELECT COUNT(*) FROM findings f
                     WHERE f.last_seen_assessment_id = a.id AND f.state = 'open') AS open_finding_count
                FROM assessments a
                JOIN engagements e ON e.id = a.engagement_id
                ORDER BY a.started_at DESC
                LIMIT 50
                "#,
            )
            .fetch_all(pool)
            .await?
        };
        Ok(rows.iter().map(assessment_from_row).collect())
    }

    pub async fn list_findings(
        &self,
        assessment_id: Option<&str>,
        engagement_id: Option<&str>,
        working_dir: Option<&str>,
    ) -> Result<Vec<Finding>> {
        let pool = self.pool().await?;
        let rows = if let Some(id) = assessment_id {
            sqlx::query(
                "SELECT * FROM findings WHERE last_seen_assessment_id = ? ORDER BY severity, path LIMIT 500",
            )
            .bind(id)
            .fetch_all(pool)
            .await?
        } else if let Some(id) = engagement_id {
            sqlx::query(
                "SELECT * FROM findings WHERE engagement_id = ? AND state = 'open' ORDER BY severity, path LIMIT 500",
            )
            .bind(id)
            .fetch_all(pool)
            .await?
        } else if let Some(dir) = working_dir {
            let dir = normalize_working_dir_for_query(dir);
            sqlx::query(
                r#"
                SELECT f.* FROM findings f
                JOIN engagements e ON e.id = f.engagement_id
                WHERE e.working_dir = ? AND f.state = 'open'
                ORDER BY f.last_seen_at DESC
                LIMIT 500
                "#,
            )
            .bind(dir)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query(
                "SELECT * FROM findings WHERE state = 'open' ORDER BY last_seen_at DESC LIMIT 200",
            )
            .fetch_all(pool)
            .await?
        };
        Ok(rows.iter().map(finding_from_row).collect())
    }
}

pub fn canonicalize_working_dir(path: &str) -> Result<String> {
    let input = PathBuf::from(path.trim());
    anyhow::ensure!(!path.trim().is_empty(), "working_dir is required");
    let abs = if input.is_absolute() {
        input
    } else {
        std::env::current_dir()?.join(input)
    };
    let canon = abs.canonicalize().unwrap_or(abs);
    anyhow::ensure!(
        canon.is_dir(),
        "working_dir is not a directory: {}",
        canon.display()
    );
    Ok(canon.to_string_lossy().to_string())
}

pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn preview_from_payload(payload: &serde_json::Value) -> String {
    if let Some(preview) = payload.get("preview").and_then(|v| v.as_str()) {
        return preview.chars().take(2_000).collect();
    }
    serde_json::to_string(payload)
        .unwrap_or_default()
        .chars()
        .take(2_000)
        .collect()
}

fn json_value(raw: &str) -> serde_json::Value {
    serde_json::from_str(raw).unwrap_or(serde_json::Value::Null)
}

fn normalize_working_dir_for_query(path: &str) -> String {
    canonicalize_working_dir(path).unwrap_or_else(|_| path.trim().to_string())
}

fn engagement_from_row(row: &sqlx::sqlite::SqliteRow) -> Engagement {
    Engagement {
        id: row.get("id"),
        working_dir: row.get("working_dir"),
        display_name: row.get("display_name"),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
        last_assessment_at: row.get("last_assessment_at"),
        status: row.get("status"),
    }
}

fn assessment_from_row(row: &sqlx::sqlite::SqliteRow) -> Assessment {
    let phases: String = row.get("phases_json");
    let stats: String = row.get("stats_json");
    let status: String = row.get("status");
    Assessment {
        id: row.get("id"),
        engagement_id: row.get("engagement_id"),
        working_dir: row.get("working_dir"),
        session_id: row.get("session_id"),
        mode: row.get("mode"),
        status: AssessmentStatus::parse(&status),
        started_at: row.get("started_at"),
        finished_at: row.get("finished_at"),
        updated_at: row.get("updated_at"),
        phases_json: json_value(&phases),
        stats_json: json_value(&stats),
        error_message: row.get("error_message"),
        trigger: row.get("trigger"),
        parent_assessment_id: row.get("parent_assessment_id"),
        open_finding_count: row.get("open_finding_count"),
    }
}

fn finding_from_row(row: &sqlx::sqlite::SqliteRow) -> Finding {
    let cwe: String = row.get("cwe_json");
    let cve: String = row.get("cve_json");
    let evidence: String = row.get("evidence_json");
    Finding {
        id: row.get("id"),
        engagement_id: row.get("engagement_id"),
        assessment_id: row.get("assessment_id"),
        last_seen_assessment_id: row.get("last_seen_assessment_id"),
        fingerprint: row.get("fingerprint"),
        state: row.get("state"),
        severity: row.get("severity"),
        confidence: row.get("confidence"),
        category: row.get("category"),
        rule_id: row.get("rule_id"),
        title: row.get("title"),
        description: row.get("description"),
        path: row.get("path"),
        line_start: row.get("line_start"),
        line_end: row.get("line_end"),
        cwe_json: json_value(&cwe),
        cve_json: json_value(&cve),
        evidence_json: json_value(&evidence),
        first_seen_at: row.get("first_seen_at"),
        last_seen_at: row.get("last_seen_at"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    #[tokio::test]
    async fn persists_engagement_assessment_and_finding() {
        let dir = tempfile::tempdir().unwrap();
        let store = AchillesStore::new(dir.path().to_path_buf());
        let engagement = store
            .upsert_engagement(dir.path().to_str().unwrap())
            .await
            .unwrap();
        let assessment = store
            .create_assessment(&engagement, None, "quick", "scan_cta", None)
            .await
            .unwrap();
        store
            .upsert_finding(
                &engagement.id,
                &assessment.id,
                &NewFinding {
                    fingerprint: "secrets|aws|demo".into(),
                    severity: Severity::High,
                    confidence: "high".into(),
                    category: "secrets".into(),
                    rule_id: "aws-access-key".into(),
                    title: "AWS access key".into(),
                    description: "test".into(),
                    path: Some("env".into()),
                    line_start: Some(1),
                    line_end: Some(1),
                    cwe: vec!["CWE-798".into()],
                    cve: vec![],
                    evidence: serde_json::json!({"preview": "AKIA…"}),
                },
            )
            .await
            .unwrap();
        let listed = store
            .list_findings(Some(&assessment.id), None, None)
            .await
            .unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].title, "AWS access key");
    }
}
