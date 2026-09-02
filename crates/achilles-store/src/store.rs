//! SQLite `achilles.db` access. Apache-2.0.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Result;
use sha2::{Digest, Sha256};
use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
use sqlx::{Pool, Row, Sqlite};
use tokio::sync::OnceCell;
use uuid::Uuid;

use crate::types::{
    Assessment, AssessmentStatus, Candidate, CandidateStatus, CoverageSnapshot, Engagement,
    Finding, FindingEvent, HandleBlob, NewFinding, WorkUnit, WorkUnitDecision,
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
                base_git_sha TEXT,
                head_git_sha TEXT,
                content_fingerprint TEXT,
                model_class TEXT,
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
                status_reason TEXT,
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
                error_message TEXT,
                argv_fingerprint TEXT,
                output_handle_id TEXT
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
            "CREATE INDEX IF NOT EXISTS idx_assessments_session ON assessments(session_id)",
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

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS intel_cache (
                cache_key TEXT PRIMARY KEY,
                source TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                fetched_at TEXT NOT NULL
            );
            "#,
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS finding_events (
                id TEXT PRIMARY KEY,
                finding_id TEXT NOT NULL,
                at TEXT NOT NULL,
                actor TEXT NOT NULL,
                from_state TEXT,
                to_state TEXT,
                assessment_id TEXT,
                detail_json TEXT NOT NULL DEFAULT '{}',
                FOREIGN KEY(finding_id) REFERENCES findings(id)
            );
            "#,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_finding_events_finding ON finding_events(finding_id)",
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS coverage_snapshots (
                assessment_id TEXT PRIMARY KEY,
                files_indexed INTEGER NOT NULL DEFAULT 0,
                paths_json TEXT NOT NULL DEFAULT '[]',
                skipped_globs_json TEXT NOT NULL DEFAULT '[]',
                skipped_engines_json TEXT NOT NULL DEFAULT '[]',
                created_at TEXT NOT NULL,
                FOREIGN KEY(assessment_id) REFERENCES assessments(id)
            );
            "#,
        )
        .execute(&mut *tx)
        .await?;

        add_column_if_missing(&mut tx, "assessments", "base_git_sha", "TEXT").await?;
        add_column_if_missing(&mut tx, "assessments", "head_git_sha", "TEXT").await?;
        add_column_if_missing(&mut tx, "assessments", "content_fingerprint", "TEXT").await?;
        add_column_if_missing(&mut tx, "assessments", "model_class", "TEXT").await?;
        add_column_if_missing(&mut tx, "assessments", "max_duration_secs", "INTEGER").await?;
        add_column_if_missing(&mut tx, "assessments", "max_cost_usd", "REAL").await?;
        add_column_if_missing(&mut tx, "findings", "status_reason", "TEXT").await?;
        add_column_if_missing(&mut tx, "engine_runs", "argv_fingerprint", "TEXT").await?;
        add_column_if_missing(&mut tx, "engine_runs", "output_handle_id", "TEXT").await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS candidates (
                id TEXT PRIMARY KEY,
                engagement_id TEXT NOT NULL,
                assessment_id TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                path TEXT,
                line_start INTEGER,
                line_end INTEGER,
                matcher_or_engine TEXT NOT NULL,
                snippet_redacted TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending',
                finding_id TEXT,
                payload_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                UNIQUE(assessment_id, fingerprint)
            );
            "#,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_candidates_assessment ON candidates(assessment_id, status)",
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS work_units (
                id TEXT PRIMARY KEY,
                assessment_id TEXT NOT NULL,
                kind TEXT NOT NULL,
                key TEXT NOT NULL,
                input_digest TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                locked_by_run_id TEXT,
                updated_at TEXT NOT NULL,
                UNIQUE(assessment_id, kind, key)
            );
            "#,
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_work_units_assessment ON work_units(assessment_id, status)",
        )
        .execute(&mut *tx)
        .await?;

        sqlx::query("INSERT OR IGNORE INTO schema_version (version) VALUES (1)")
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT OR IGNORE INTO schema_version (version) VALUES (2)")
            .execute(&mut *tx)
            .await?;
        sqlx::query("INSERT OR IGNORE INTO schema_version (version) VALUES (3)")
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
        let parent_head: Option<String> = if let Some(parent_id) = parent_assessment_id {
            sqlx::query("SELECT head_git_sha FROM assessments WHERE id = ?")
                .bind(parent_id)
                .fetch_optional(pool)
                .await?
                .and_then(|row| row.get::<Option<String>, _>("head_git_sha"))
        } else {
            None
        };
        let phases = serde_json::json!({
            "fingerprint": "queued",
            "secrets": "queued",
            "surfaces": "queued",
            "sca": "queued",
            "intel": "queued"
        });
        let stats = serde_json::json!({});
        sqlx::query(
            r#"
            INSERT INTO assessments (
                id, engagement_id, session_id, mode, status, started_at, updated_at,
                parent_assessment_id, phases_json, stats_json, trigger, base_git_sha
            ) VALUES (?, ?, ?, ?, 'running', ?, ?, ?, ?, ?, ?, ?)
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
        .bind(&parent_head)
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
            base_git_sha: parent_head,
            head_git_sha: None,
            content_fingerprint: None,
            model_class: None,
            open_finding_count: 0,
            new_finding_count: None,
            gone_finding_count: None,
        })
    }

    pub async fn set_scan_identity(
        &self,
        assessment_id: &str,
        head_git_sha: Option<&str>,
        content_fingerprint: &str,
        model_class: &str,
    ) -> Result<()> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        sqlx::query(
            r#"
            UPDATE assessments
            SET head_git_sha = ?,
                content_fingerprint = ?,
                model_class = ?,
                base_git_sha = COALESCE(base_git_sha, ?),
                updated_at = ?
            WHERE id = ?
            "#,
        )
        .bind(head_git_sha)
        .bind(content_fingerprint)
        .bind(model_class)
        .bind(head_git_sha)
        .bind(now)
        .bind(assessment_id)
        .execute(pool)
        .await?;
        Ok(())
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
        let result = sqlx::query(
            r#"
            UPDATE assessments
            SET status = ?, finished_at = ?, updated_at = ?, stats_json = ?, error_message = ?
            WHERE id = ? AND status IN ('running', 'queued', 'paused')
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
        if result.rows_affected() == 0 {
            return Ok(());
        }

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

    pub async fn set_live_status(
        &self,
        assessment_id: &str,
        status: AssessmentStatus,
    ) -> Result<()> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        sqlx::query(
            r#"
            UPDATE assessments
            SET status = ?, updated_at = ?, finished_at = NULL
            WHERE id = ? AND status IN ('running', 'queued', 'paused')
            "#,
        )
        .bind(status.as_str())
        .bind(now)
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
        self.record_engine_run_with(
            assessment_id,
            engine,
            status,
            summary,
            error_message,
            None,
            None,
        )
        .await
    }

    pub async fn record_engine_run_with(
        &self,
        assessment_id: &str,
        engine: &str,
        status: &str,
        summary: serde_json::Value,
        error_message: Option<&str>,
        argv_fingerprint: Option<&str>,
        output_handle_id: Option<&str>,
    ) -> Result<()> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO engine_runs (
                id, assessment_id, engine, status, started_at, finished_at,
                summary_json, error_message, argv_fingerprint, output_handle_id
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        .bind(argv_fingerprint)
        .bind(output_handle_id)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_coverage_snapshot(
        &self,
        assessment_id: &str,
        files_indexed: i64,
        paths: serde_json::Value,
        skipped_globs: serde_json::Value,
    ) -> Result<()> {
        let pool = self.pool().await?;
        let skipped_engines = sqlx::query(
            "SELECT engine, summary_json FROM engine_runs WHERE assessment_id = ? AND status = 'skipped'",
        )
        .bind(assessment_id)
        .fetch_all(pool)
        .await?;
        let skipped_engines_json = serde_json::Value::Array(
            skipped_engines
                .iter()
                .map(|row| {
                    let engine: String = row.get("engine");
                    let summary = json_value(&row.get::<String, _>("summary_json"));
                    let reason = summary
                        .get("reason")
                        .and_then(|v| v.as_str())
                        .unwrap_or("skipped");
                    serde_json::json!({ "engine": engine, "reason": reason })
                })
                .collect(),
        );
        let now = now_rfc3339();
        sqlx::query(
            r#"
            INSERT INTO coverage_snapshots (
                assessment_id, files_indexed, paths_json, skipped_globs_json,
                skipped_engines_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(assessment_id) DO UPDATE SET
                files_indexed = excluded.files_indexed,
                paths_json = excluded.paths_json,
                skipped_globs_json = excluded.skipped_globs_json,
                skipped_engines_json = excluded.skipped_engines_json,
                created_at = excluded.created_at
            "#,
        )
        .bind(assessment_id)
        .bind(files_indexed)
        .bind(paths.to_string())
        .bind(skipped_globs.to_string())
        .bind(skipped_engines_json.to_string())
        .bind(&now)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn get_coverage_snapshot(
        &self,
        assessment_id: &str,
    ) -> Result<Option<CoverageSnapshot>> {
        let pool = self.pool().await?;
        let row = sqlx::query(
            r#"
            SELECT assessment_id, files_indexed, paths_json, skipped_globs_json,
                   skipped_engines_json, created_at
            FROM coverage_snapshots WHERE assessment_id = ?
            "#,
        )
        .bind(assessment_id)
        .fetch_optional(pool)
        .await?;
        Ok(row.as_ref().map(|row| CoverageSnapshot {
            assessment_id: row.get("assessment_id"),
            files_indexed: row.get("files_indexed"),
            paths_json: json_value(&row.get::<String, _>("paths_json")),
            skipped_globs_json: json_value(&row.get::<String, _>("skipped_globs_json")),
            skipped_engines_json: json_value(&row.get::<String, _>("skipped_engines_json")),
            created_at: row.get("created_at"),
        }))
    }

    pub async fn list_finding_events(&self, finding_id: &str) -> Result<Vec<FindingEvent>> {
        let pool = self.pool().await?;
        let rows = sqlx::query(
            r#"
            SELECT id, finding_id, at, actor, from_state, to_state, assessment_id, detail_json
            FROM finding_events WHERE finding_id = ? ORDER BY at ASC, id ASC
            "#,
        )
        .bind(finding_id)
        .fetch_all(pool)
        .await?;
        Ok(rows.iter().map(finding_event_from_row).collect())
    }

    pub async fn merge_stats(&self, assessment_id: &str, patch: serde_json::Value) -> Result<()> {
        let pool = self.pool().await?;
        let row = sqlx::query("SELECT stats_json FROM assessments WHERE id = ?")
            .bind(assessment_id)
            .fetch_one(pool)
            .await?;
        let raw: String = row.get("stats_json");
        let mut stats: serde_json::Value =
            serde_json::from_str(&raw).unwrap_or(serde_json::json!({}));
        if let (Some(dst), Some(src)) = (stats.as_object_mut(), patch.as_object()) {
            for (key, value) in src {
                dst.insert(key.clone(), value.clone());
            }
        }
        let now = now_rfc3339();
        sqlx::query("UPDATE assessments SET stats_json = ?, updated_at = ? WHERE id = ?")
            .bind(stats.to_string())
            .bind(now)
            .bind(assessment_id)
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

    /// Copy `achilles.db` next to a checkpointed WAL. Best-effort; scans still complete if this fails.
    pub async fn backup_now(&self) -> Result<PathBuf> {
        let pool = self.pool().await?;
        let _ = sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(pool)
            .await;
        let src = self.root.join(DB_NAME);
        let dest_dir = self.root.join("backups");
        std::fs::create_dir_all(&dest_dir)?;
        let stamp = now_rfc3339().replace(':', "");
        let dest = dest_dir.join(format!("achilles-{stamp}.db"));
        std::fs::copy(&src, &dest)?;
        Ok(dest)
    }

    pub async fn get_handle(
        &self,
        handle_id: &str,
        include_payload: bool,
    ) -> Result<Option<HandleBlob>> {
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

    pub async fn intel_cache_get(
        &self,
        key: &str,
        max_age_secs: i64,
    ) -> Result<Option<serde_json::Value>> {
        let pool = self.pool().await?;
        let row =
            sqlx::query("SELECT payload_json, fetched_at FROM intel_cache WHERE cache_key = ?")
                .bind(key)
                .fetch_optional(pool)
                .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let fetched: String = row.get("fetched_at");
        let Ok(ts) = chrono::DateTime::parse_from_rfc3339(&fetched) else {
            return Ok(None);
        };
        let age = chrono::Utc::now().signed_duration_since(ts.with_timezone(&chrono::Utc));
        if age.num_seconds() > max_age_secs {
            return Ok(None);
        }
        let raw: String = row.get("payload_json");
        Ok(serde_json::from_str(&raw).ok())
    }

    pub async fn intel_cache_put(
        &self,
        key: &str,
        source: &str,
        payload: &serde_json::Value,
    ) -> Result<()> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        sqlx::query(
            r#"
            INSERT INTO intel_cache (cache_key, source, payload_json, fetched_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(cache_key) DO UPDATE SET
                source = excluded.source,
                payload_json = excluded.payload_json,
                fetched_at = excluded.fetched_at
            "#,
        )
        .bind(key)
        .bind(source)
        .bind(payload.to_string())
        .bind(now)
        .execute(pool)
        .await?;
        Ok(())
    }

    pub async fn upsert_finding(
        &self,
        engagement_id: &str,
        assessment_id: &str,
        finding: &NewFinding,
    ) -> Result<()> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        let existing = sqlx::query(
            "SELECT id, state, evidence_json FROM findings WHERE engagement_id = ? AND fingerprint = ?",
        )
        .bind(engagement_id)
        .bind(&finding.fingerprint)
        .fetch_optional(pool)
        .await?;
        let mut evidence = finding.evidence.clone();
        if let Some(row) = &existing {
            let prev: String = row.get("evidence_json");
            let prev_json = json_value(&prev);
            evidence = crate::engines::investigate::preserve_agent_passes(&prev_json, evidence);
            evidence = crate::engines::investigate::preserve_triage(&prev_json, evidence);
        }
        let cwe = serde_json::to_string(&finding.cwe)?;
        let cve = serde_json::to_string(&finding.cve)?;
        let evidence_s = evidence.to_string();
        if let Some(row) = existing {
            let id: String = row.get("id");
            let prev_state: String = row.get("state");
            sqlx::query(
                r#"
                UPDATE findings SET
                    last_seen_assessment_id = ?,
                    last_seen_at = ?,
                    severity = ?,
                    confidence = ?,
                    title = ?,
                    description = ?,
                    evidence_json = ?,
                    cve_json = ?,
                    status_reason = CASE
                        WHEN state = 'verified_fixed' THEN NULL
                        ELSE status_reason
                    END,
                    state = CASE
                        WHEN state = 'verified_fixed' THEN 'open'
                        ELSE state
                    END
                WHERE id = ?
                "#,
            )
            .bind(assessment_id)
            .bind(&now)
            .bind(finding.severity.as_str())
            .bind(&finding.confidence)
            .bind(&finding.title)
            .bind(&finding.description)
            .bind(evidence_s)
            .bind(cve)
            .bind(&id)
            .execute(pool)
            .await?;
            if prev_state == "verified_fixed" {
                self.insert_finding_event(
                    &id,
                    "engine",
                    Some(&prev_state),
                    Some("open"),
                    Some(assessment_id),
                    serde_json::json!({"reason": "seen_again"}),
                )
                .await?;
            }
            return Ok(());
        }
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO findings (
                id, engagement_id, assessment_id, last_seen_assessment_id, fingerprint,
                state, severity, confidence, category, rule_id, title, description,
                path, line_start, line_end, cwe_json, cve_json, evidence_json,
                first_seen_at, last_seen_at
            ) VALUES (?, ?, ?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
        .bind(evidence_s)
        .bind(&now)
        .bind(&now)
        .execute(pool)
        .await?;
        self.insert_finding_event(
            &id,
            "engine",
            None,
            Some("open"),
            Some(assessment_id),
            serde_json::json!({"ruleId": finding.rule_id}),
        )
        .await?;
        Ok(())
    }

    fn snippet_of(hit: &NewFinding) -> String {
        hit.evidence
            .get("preview")
            .and_then(|v| v.as_str())
            .unwrap_or(&hit.description)
            .chars()
            .take(400)
            .collect()
    }

    pub async fn upsert_candidate(
        &self,
        engagement_id: &str,
        assessment_id: &str,
        engine: &str,
        hit: &NewFinding,
    ) -> Result<String> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        let payload = serde_json::to_value(hit)?;
        let snippet = Self::snippet_of(hit);
        let existing = sqlx::query(
            "SELECT id, status FROM candidates WHERE assessment_id = ? AND fingerprint = ?",
        )
        .bind(assessment_id)
        .bind(&hit.fingerprint)
        .fetch_optional(pool)
        .await?;
        if let Some(row) = existing {
            let id: String = row.get("id");
            sqlx::query(
                r#"
                UPDATE candidates SET
                    path = ?, line_start = ?, line_end = ?, matcher_or_engine = ?,
                    snippet_redacted = ?, payload_json = ?
                WHERE id = ?
                "#,
            )
            .bind(&hit.path)
            .bind(hit.line_start)
            .bind(hit.line_end)
            .bind(engine)
            .bind(&snippet)
            .bind(payload.to_string())
            .bind(&id)
            .execute(pool)
            .await?;
            return Ok(id);
        }
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO candidates (
                id, engagement_id, assessment_id, fingerprint, path, line_start, line_end,
                matcher_or_engine, snippet_redacted, status, payload_json, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?, ?)
            "#,
        )
        .bind(&id)
        .bind(engagement_id)
        .bind(assessment_id)
        .bind(&hit.fingerprint)
        .bind(&hit.path)
        .bind(hit.line_start)
        .bind(hit.line_end)
        .bind(engine)
        .bind(&snippet)
        .bind(payload.to_string())
        .bind(&now)
        .execute(pool)
        .await?;
        Ok(id)
    }

    pub async fn confirm_candidate(&self, candidate_id: &str) -> Result<String> {
        let candidate = self
            .get_candidate(candidate_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("unknown candidate {candidate_id}"))?;
        let hit: NewFinding = serde_json::from_value(candidate.payload_json.clone())
            .map_err(|err| anyhow::anyhow!("candidate payload: {err}"))?;
        self.upsert_finding(&candidate.engagement_id, &candidate.assessment_id, &hit)
            .await?;
        let finding_id =
            sqlx::query("SELECT id FROM findings WHERE engagement_id = ? AND fingerprint = ?")
                .bind(&candidate.engagement_id)
                .bind(&candidate.fingerprint)
                .fetch_one(self.pool().await?)
                .await?
                .get::<String, _>("id");
        sqlx::query("UPDATE candidates SET status = 'confirmed', finding_id = ? WHERE id = ?")
            .bind(&finding_id)
            .bind(candidate_id)
            .execute(self.pool().await?)
            .await?;
        Ok(finding_id)
    }

    pub async fn reject_candidate(&self, candidate_id: &str) -> Result<()> {
        let n = sqlx::query("UPDATE candidates SET status = 'rejected' WHERE id = ?")
            .bind(candidate_id)
            .execute(self.pool().await?)
            .await?
            .rows_affected();
        anyhow::ensure!(n == 1, "unknown candidate {candidate_id}");
        Ok(())
    }

    pub async fn escalate_candidate(&self, candidate_id: &str) -> Result<String> {
        let finding_id = self.confirm_candidate(candidate_id).await?;
        sqlx::query("UPDATE candidates SET status = 'escalated' WHERE id = ?")
            .bind(candidate_id)
            .execute(self.pool().await?)
            .await?;
        Ok(finding_id)
    }

    pub async fn set_candidate_status_for_fingerprint(
        &self,
        assessment_id: &str,
        fingerprint: &str,
        status: CandidateStatus,
        finding_id: Option<&str>,
    ) -> Result<()> {
        sqlx::query(
            "UPDATE candidates SET status = ?, finding_id = COALESCE(?, finding_id) WHERE assessment_id = ? AND fingerprint = ?",
        )
        .bind(status.as_str())
        .bind(finding_id)
        .bind(assessment_id)
        .bind(fingerprint)
        .execute(self.pool().await?)
        .await?;
        Ok(())
    }

    pub async fn get_candidate(&self, candidate_id: &str) -> Result<Option<Candidate>> {
        let row = sqlx::query("SELECT * FROM candidates WHERE id = ?")
            .bind(candidate_id)
            .fetch_optional(self.pool().await?)
            .await?;
        Ok(row.as_ref().map(candidate_from_row))
    }

    pub async fn list_candidates(
        &self,
        assessment_id: &str,
        status: Option<&str>,
        engine: Option<&str>,
    ) -> Result<Vec<Candidate>> {
        let rows = sqlx::query(
            r#"
            SELECT * FROM candidates
            WHERE assessment_id = ?
              AND (? IS NULL OR status = ?)
              AND (? IS NULL OR matcher_or_engine = ?)
            ORDER BY created_at ASC
            "#,
        )
        .bind(assessment_id)
        .bind(status)
        .bind(status)
        .bind(engine)
        .bind(engine)
        .fetch_all(self.pool().await?)
        .await?;
        Ok(rows.iter().map(candidate_from_row).collect())
    }

    /// Promote leftover pending hits into findings so a scan cannot swallow them.
    pub async fn confirm_pending_candidates(&self, assessment_id: &str) -> Result<usize> {
        let pending = self
            .list_candidates(assessment_id, Some("pending"), None)
            .await?;
        let mut n = 0usize;
        for candidate in pending {
            self.confirm_candidate(&candidate.id).await?;
            n += 1;
        }
        Ok(n)
    }

    pub async fn count_pending_candidates(&self, assessment_id: &str, engine: &str) -> Result<i64> {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM candidates WHERE assessment_id = ? AND status = 'pending' AND matcher_or_engine = ?",
        )
        .bind(assessment_id)
        .bind(engine)
        .fetch_one(self.pool().await?)
        .await?;
        Ok(count)
    }

    pub async fn reclaim_stale_units(&self, assessment_id: &str) -> Result<u64> {
        let now = now_rfc3339();
        let n = sqlx::query(
            "UPDATE work_units SET status = 'pending', locked_by_run_id = NULL, updated_at = ? WHERE assessment_id = ? AND status = 'running'",
        )
        .bind(&now)
        .bind(assessment_id)
        .execute(self.pool().await?)
        .await?
        .rows_affected();
        Ok(n)
    }

    pub async fn begin_work_unit(
        &self,
        assessment_id: &str,
        kind: &str,
        key: &str,
        input_digest: &str,
        run_id: &str,
    ) -> Result<WorkUnitDecision> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        let existing = sqlx::query(
            "SELECT status, input_digest FROM work_units WHERE assessment_id = ? AND kind = ? AND key = ?",
        )
        .bind(assessment_id)
        .bind(kind)
        .bind(key)
        .fetch_optional(pool)
        .await?;
        if let Some(row) = &existing {
            let status: String = row.get("status");
            let digest: String = row.get("input_digest");
            if status == "done" && digest == input_digest {
                return Ok(WorkUnitDecision::Skip);
            }
        }
        if existing.is_some() {
            sqlx::query(
                r#"
                UPDATE work_units
                SET input_digest = ?, status = 'running', locked_by_run_id = ?, updated_at = ?
                WHERE assessment_id = ? AND kind = ? AND key = ?
                "#,
            )
            .bind(input_digest)
            .bind(run_id)
            .bind(&now)
            .bind(assessment_id)
            .bind(kind)
            .bind(key)
            .execute(pool)
            .await?;
        } else {
            let id = Uuid::new_v4().to_string();
            sqlx::query(
                r#"
                INSERT INTO work_units (
                    id, assessment_id, kind, key, input_digest, status, locked_by_run_id, updated_at
                ) VALUES (?, ?, ?, ?, ?, 'running', ?, ?)
                "#,
            )
            .bind(&id)
            .bind(assessment_id)
            .bind(kind)
            .bind(key)
            .bind(input_digest)
            .bind(run_id)
            .bind(&now)
            .execute(pool)
            .await?;
        }
        Ok(WorkUnitDecision::Run)
    }

    pub async fn finish_work_unit(
        &self,
        assessment_id: &str,
        kind: &str,
        key: &str,
        status: &str,
    ) -> Result<()> {
        let now = now_rfc3339();
        sqlx::query(
            r#"
            UPDATE work_units
            SET status = ?, locked_by_run_id = CASE WHEN ? = 'done' THEN NULL ELSE locked_by_run_id END, updated_at = ?
            WHERE assessment_id = ? AND kind = ? AND key = ?
            "#,
        )
        .bind(status)
        .bind(status)
        .bind(&now)
        .bind(assessment_id)
        .bind(kind)
        .bind(key)
        .execute(self.pool().await?)
        .await?;
        Ok(())
    }

    pub async fn list_work_units(&self, assessment_id: &str) -> Result<Vec<WorkUnit>> {
        let rows =
            sqlx::query("SELECT * FROM work_units WHERE assessment_id = ? ORDER BY updated_at ASC")
                .bind(assessment_id)
                .fetch_all(self.pool().await?)
                .await?;
        Ok(rows.iter().map(work_unit_from_row).collect())
    }

    pub async fn reopen_assessment(&self, assessment_id: &str) -> Result<()> {
        let now = now_rfc3339();
        let n = sqlx::query(
            r#"
            UPDATE assessments
            SET status = 'running', finished_at = NULL, error_message = NULL, updated_at = ?
            WHERE id = ? AND status IN ('cancelled', 'partial', 'paused', 'failed', 'running')
            "#,
        )
        .bind(&now)
        .bind(assessment_id)
        .execute(self.pool().await?)
        .await?
        .rows_affected();
        anyhow::ensure!(n == 1, "assessment {assessment_id} cannot be resumed");
        Ok(())
    }

    pub async fn set_scan_caps(
        &self,
        assessment_id: &str,
        max_duration_secs: Option<u64>,
        max_cost_usd: Option<f64>,
    ) -> Result<()> {
        sqlx::query("UPDATE assessments SET max_duration_secs = ?, max_cost_usd = ? WHERE id = ?")
            .bind(max_duration_secs.map(|v| v as i64))
            .bind(max_cost_usd)
            .bind(assessment_id)
            .execute(self.pool().await?)
            .await?;
        Ok(())
    }

    pub async fn latest_resumable_assessment(
        &self,
        working_dir: &str,
    ) -> Result<Option<Assessment>> {
        let listed = self.list_assessments(Some(working_dir)).await?;
        Ok(listed.into_iter().find(|a| {
            matches!(
                a.status,
                AssessmentStatus::Cancelled
                    | AssessmentStatus::Partial
                    | AssessmentStatus::Paused
                    | AssessmentStatus::Failed
            )
        }))
    }

    pub fn is_resumable_status(status: AssessmentStatus) -> bool {
        matches!(
            status,
            AssessmentStatus::Cancelled
                | AssessmentStatus::Partial
                | AssessmentStatus::Paused
                | AssessmentStatus::Failed
                | AssessmentStatus::Running
        )
    }

    pub async fn get_finding(&self, finding_id: &str) -> Result<Option<Finding>> {
        let pool = self.pool().await?;
        let row = sqlx::query("SELECT * FROM findings WHERE id = ?")
            .bind(finding_id)
            .fetch_optional(pool)
            .await?;
        Ok(row.as_ref().map(finding_from_row))
    }

    pub async fn set_finding_state(&self, finding_id: &str, state: &str) -> Result<Finding> {
        self.triage_finding(finding_id, state, None).await
    }

    pub async fn triage_finding(
        &self,
        finding_id: &str,
        state: &str,
        reason: Option<&str>,
    ) -> Result<Finding> {
        anyhow::ensure!(
            matches!(state, "open" | "confirmed" | "dismissed" | "verified_fixed"),
            "invalid finding state {state}"
        );
        let reason = reason.map(str::trim).filter(|value| !value.is_empty());
        if let Some(reason) = reason {
            anyhow::ensure!(reason == "false_positive", "invalid triage reason {reason}");
            anyhow::ensure!(
                state == "dismissed",
                "false_positive is only valid when dismissing"
            );
        }
        let mut finding = self
            .get_finding(finding_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("unknown finding {finding_id}"))?;
        let now = now_rfc3339();
        let from_state = finding.state.clone();
        let mut evidence = finding.evidence_json.clone();
        if !evidence.is_object() {
            evidence = serde_json::json!({});
        }
        if let serde_json::Value::Object(map) = &mut evidence {
            if state == "dismissed" && reason == Some("false_positive") {
                map.insert(
                    "triage".into(),
                    serde_json::json!({
                        "reason": "false_positive",
                        "source": "user",
                        "at": now,
                    }),
                );
            } else if state != "dismissed" {
                map.remove("triage");
            }
        }
        let status_reason = if state == "dismissed" { reason } else { None };
        let pool = self.pool().await?;
        let n = sqlx::query(
            "UPDATE findings SET state = ?, status_reason = ?, evidence_json = ?, last_seen_at = ? WHERE id = ?",
        )
        .bind(state)
        .bind(status_reason)
        .bind(evidence.to_string())
        .bind(&now)
        .bind(finding_id)
        .execute(pool)
        .await?
        .rows_affected();
        anyhow::ensure!(n == 1, "unknown finding {finding_id}");
        if from_state != state {
            self.insert_finding_event(
                finding_id,
                "user",
                Some(&from_state),
                Some(state),
                Some(&finding.assessment_id),
                match status_reason {
                    Some(reason) => serde_json::json!({"reason": reason}),
                    None => serde_json::json!({}),
                },
            )
            .await?;
        }
        finding.state = state.to_string();
        finding.status_reason = status_reason.map(str::to_string);
        finding.evidence_json = evidence;
        finding.last_seen_at = now;
        Ok(finding)
    }

    pub async fn set_finding_verdict(
        &self,
        finding_id: &str,
        role: &str,
        verdict: &str,
        reason: &str,
    ) -> Result<Finding> {
        let role = crate::engines::investigate::parse_verdict_role(role)
            .ok_or_else(|| anyhow::anyhow!("role must be investigator or validator"))?;
        let verdict = crate::engines::investigate::parse_verdict(verdict).ok_or_else(|| {
            anyhow::anyhow!("verdict must be true_positive, false_positive, or uncertain")
        })?;
        let reason = reason.trim();
        anyhow::ensure!(!reason.is_empty(), "reason is required");
        anyhow::ensure!(
            reason.len() <= crate::engines::investigate::MAX_VERDICT_REASON,
            "reason too long"
        );
        let mut finding = self
            .get_finding(finding_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("unknown finding {finding_id}"))?;
        let now = now_rfc3339();
        let mut evidence = finding.evidence_json.clone();
        if !evidence.is_object() {
            evidence = serde_json::json!({});
        }
        let pass = serde_json::json!({
            "verdict": verdict,
            "reason": reason,
            "at": now,
        });
        if let serde_json::Value::Object(map) = &mut evidence {
            let inv = map
                .entry("investigation".to_string())
                .or_insert_with(|| serde_json::json!({}));
            if let serde_json::Value::Object(inv_map) = inv {
                let passes = inv_map
                    .entry("passes".to_string())
                    .or_insert_with(|| serde_json::json!({}));
                if let serde_json::Value::Object(passes_map) = passes {
                    passes_map.insert(role.to_string(), pass);
                }
                if role == "validator" {
                    inv_map.insert("needsAgent".into(), serde_json::json!(false));
                }
            }
        }
        let pool = self.pool().await?;
        let n = sqlx::query("UPDATE findings SET evidence_json = ?, last_seen_at = ? WHERE id = ?")
            .bind(evidence.to_string())
            .bind(&now)
            .bind(finding_id)
            .execute(pool)
            .await?
            .rows_affected();
        anyhow::ensure!(n == 1, "unknown finding {finding_id}");
        finding.evidence_json = evidence;
        finding.last_seen_at = now;
        Ok(finding)
    }

    /// Open/confirmed findings not seen on this assessment are treated as gone from the tree.
    pub async fn close_absent_findings(
        &self,
        engagement_id: &str,
        assessment_id: &str,
    ) -> Result<u64> {
        self.close_absent_findings_except(engagement_id, assessment_id, &[])
            .await
    }

    /// Like [`Self::close_absent_findings`], but keep open findings in `skip_categories`
    /// (used when an optional engine did not run this scan).
    pub async fn close_absent_findings_except(
        &self,
        engagement_id: &str,
        assessment_id: &str,
        skip_categories: &[&str],
    ) -> Result<u64> {
        let pool = self.pool().await?;
        let now = now_rfc3339();
        let closing = sqlx::query(
            r#"
            SELECT id, state, category FROM findings
            WHERE engagement_id = ?
              AND state IN ('open', 'confirmed')
              AND last_seen_assessment_id != ?
            "#,
        )
        .bind(engagement_id)
        .bind(assessment_id)
        .fetch_all(pool)
        .await?;
        let mut closed = 0u64;
        for row in closing {
            let category: String = row.get("category");
            if skip_categories
                .iter()
                .any(|skip| skip.eq_ignore_ascii_case(&category))
            {
                continue;
            }
            let id: String = row.get("id");
            let from_state: String = row.get("state");
            let n = sqlx::query(
                r#"
                UPDATE findings
                SET state = 'verified_fixed',
                    status_reason = 'absent_from_scan',
                    last_seen_assessment_id = ?,
                    last_seen_at = ?
                WHERE id = ?
                "#,
            )
            .bind(assessment_id)
            .bind(&now)
            .bind(&id)
            .execute(pool)
            .await?
            .rows_affected();
            closed += n;
            self.insert_finding_event(
                &id,
                "engine",
                Some(&from_state),
                Some("verified_fixed"),
                Some(assessment_id),
                serde_json::json!({"reason": "absent_from_scan"}),
            )
            .await?;
        }
        Ok(closed)
    }

    async fn insert_finding_event(
        &self,
        finding_id: &str,
        actor: &str,
        from_state: Option<&str>,
        to_state: Option<&str>,
        assessment_id: Option<&str>,
        detail: serde_json::Value,
    ) -> Result<()> {
        let pool = self.pool().await?;
        let id = Uuid::new_v4().to_string();
        sqlx::query(
            r#"
            INSERT INTO finding_events (
                id, finding_id, at, actor, from_state, to_state, assessment_id, detail_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(&id)
        .bind(finding_id)
        .bind(now_rfc3339())
        .bind(actor)
        .bind(from_state)
        .bind(to_state)
        .bind(assessment_id)
        .bind(detail.to_string())
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
                 WHERE f.last_seen_assessment_id = a.id AND f.state IN ('open', 'confirmed')) AS open_finding_count
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
                     WHERE f.last_seen_assessment_id = a.id AND f.state IN ('open', 'confirmed')) AS open_finding_count
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
                     WHERE f.last_seen_assessment_id = a.id AND f.state IN ('open', 'confirmed')) AS open_finding_count
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

    pub async fn list_assessments_for_session(&self, session_id: &str) -> Result<Vec<Assessment>> {
        let pool = self.pool().await?;
        let rows = sqlx::query(
            r#"
            SELECT a.*, e.working_dir,
                (SELECT COUNT(*) FROM findings f
                 WHERE f.last_seen_assessment_id = a.id AND f.state IN ('open', 'confirmed')) AS open_finding_count
            FROM assessments a
            JOIN engagements e ON e.id = a.engagement_id
            WHERE a.session_id = ?
            ORDER BY a.started_at DESC
            LIMIT 50
            "#,
        )
        .bind(session_id)
        .fetch_all(pool)
        .await?;
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
                "SELECT * FROM findings WHERE engagement_id = ? AND state IN ('open', 'confirmed') ORDER BY severity, path LIMIT 500",
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
                WHERE e.working_dir = ? AND f.state IN ('open', 'confirmed')
                ORDER BY f.last_seen_at DESC
                LIMIT 500
                "#,
            )
            .bind(dir)
            .fetch_all(pool)
            .await?
        } else {
            sqlx::query(
                "SELECT * FROM findings WHERE state IN ('open', 'confirmed') ORDER BY last_seen_at DESC LIMIT 200",
            )
            .fetch_all(pool)
            .await?
        };
        Ok(rows.iter().map(finding_from_row).collect())
    }

    /// UI/history: findings that originated on this scan or are still attributed to it.
    /// Engine code should keep using [`Self::list_findings`] (last-seen only).
    pub async fn list_findings_history(
        &self,
        assessment_id: Option<&str>,
        engagement_id: Option<&str>,
        working_dir: Option<&str>,
    ) -> Result<Vec<Finding>> {
        let Some(id) = assessment_id else {
            return self
                .list_findings(None, engagement_id, working_dir)
                .await;
        };
        let pool = self.pool().await?;
        let rows = sqlx::query(
            r#"
            SELECT * FROM findings
            WHERE last_seen_assessment_id = ? OR assessment_id = ?
            ORDER BY severity, path
            LIMIT 500
            "#,
        )
        .bind(id)
        .bind(id)
        .fetch_all(pool)
        .await?;
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
    let stats_value = json_value(&stats);
    let parent_id: Option<String> = row.get("parent_assessment_id");
    let rescan = parent_id.is_some();
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
        stats_json: stats_value.clone(),
        error_message: row.get("error_message"),
        trigger: row.get("trigger"),
        parent_assessment_id: parent_id,
        base_git_sha: row.get("base_git_sha"),
        head_git_sha: row.get("head_git_sha"),
        content_fingerprint: row.get("content_fingerprint"),
        model_class: row.get("model_class"),
        open_finding_count: row.get("open_finding_count"),
        new_finding_count: if rescan {
            stats_value.get("newThisScan").and_then(|v| v.as_i64())
        } else {
            None
        },
        gone_finding_count: if rescan {
            stats_value.get("goneThisScan").and_then(|v| v.as_i64())
        } else {
            None
        },
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
        status_reason: row.get("status_reason"),
    }
}

fn candidate_from_row(row: &sqlx::sqlite::SqliteRow) -> Candidate {
    let payload: String = row.get("payload_json");
    Candidate {
        id: row.get("id"),
        engagement_id: row.get("engagement_id"),
        assessment_id: row.get("assessment_id"),
        fingerprint: row.get("fingerprint"),
        path: row.get("path"),
        line_start: row.get("line_start"),
        line_end: row.get("line_end"),
        matcher_or_engine: row.get("matcher_or_engine"),
        snippet_redacted: row.get("snippet_redacted"),
        status: CandidateStatus::parse(&row.get::<String, _>("status")),
        finding_id: row.get("finding_id"),
        payload_json: json_value(&payload),
        created_at: row.get("created_at"),
    }
}

fn work_unit_from_row(row: &sqlx::sqlite::SqliteRow) -> WorkUnit {
    WorkUnit {
        id: row.get("id"),
        assessment_id: row.get("assessment_id"),
        kind: row.get("kind"),
        key: row.get("key"),
        input_digest: row.get("input_digest"),
        status: row.get("status"),
        locked_by_run_id: row.get("locked_by_run_id"),
        updated_at: row.get("updated_at"),
    }
}

fn finding_event_from_row(row: &sqlx::sqlite::SqliteRow) -> FindingEvent {
    let detail: String = row.get("detail_json");
    FindingEvent {
        id: row.get("id"),
        finding_id: row.get("finding_id"),
        at: row.get("at"),
        actor: row.get("actor"),
        from_state: row.get("from_state"),
        to_state: row.get("to_state"),
        assessment_id: row.get("assessment_id"),
        detail_json: json_value(&detail),
    }
}

async fn add_column_if_missing(
    tx: &mut sqlx::Transaction<'_, Sqlite>,
    table: &str,
    column: &str,
    decl: &str,
) -> Result<()> {
    let rows = sqlx::query(&format!("PRAGMA table_info({table})"))
        .fetch_all(&mut **tx)
        .await?;
    let exists = rows.iter().any(|row| {
        let name: String = row.get("name");
        name == column
    });
    if !exists {
        sqlx::query(&format!("ALTER TABLE {table} ADD COLUMN {column} {decl}"))
            .execute(&mut **tx)
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CandidateStatus, Severity, WorkUnitDecision};

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
        let opened = store.list_finding_events(&listed[0].id).await.unwrap();
        assert!(
            opened
                .iter()
                .any(|event| event.actor == "engine" && event.to_state.as_deref() == Some("open")),
            "{opened:?}"
        );

        store
            .set_finding_state(&listed[0].id, "dismissed")
            .await
            .unwrap();
        let dismissed = store.get_finding(&listed[0].id).await.unwrap().unwrap();
        assert_eq!(dismissed.state, "dismissed");

        store
            .set_finding_state(&listed[0].id, "open")
            .await
            .unwrap();
        let marked = store
            .triage_finding(&listed[0].id, "dismissed", Some("false_positive"))
            .await
            .unwrap();
        assert_eq!(marked.state, "dismissed");
        assert_eq!(marked.status_reason.as_deref(), Some("false_positive"));
        assert_eq!(
            marked.evidence_json["triage"]["reason"],
            serde_json::json!("false_positive")
        );
        let events = store.list_finding_events(&listed[0].id).await.unwrap();
        assert!(
            events.iter().any(|event| {
                event.actor == "user"
                    && event.from_state.as_deref() == Some("open")
                    && event.to_state.as_deref() == Some("dismissed")
            }),
            "{events:?}"
        );
        let reopened = store
            .set_finding_state(&listed[0].id, "open")
            .await
            .unwrap();
        assert_eq!(reopened.state, "open");
        assert!(reopened.status_reason.is_none());
        assert!(reopened.evidence_json.get("triage").is_none());

        let written = store
            .set_finding_verdict(
                &listed[0].id,
                "investigator",
                "false_positive",
                "fixture token, not a live key",
            )
            .await
            .unwrap();
        assert_eq!(
            written.evidence_json["investigation"]["passes"]["investigator"]["verdict"],
            serde_json::json!("false_positive")
        );

        let second = store
            .create_assessment(&engagement, None, "quick", "scan_cta", None)
            .await
            .unwrap();
        store
            .upsert_finding(
                &engagement.id,
                &second.id,
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
        let kept = store.get_finding(&listed[0].id).await.unwrap().unwrap();
        assert_eq!(
            kept.evidence_json["investigation"]["passes"]["investigator"]["verdict"],
            serde_json::json!("false_positive")
        );
    }

    #[tokio::test]
    async fn history_list_keeps_findings_on_earlier_scan() {
        let dir = tempfile::tempdir().unwrap();
        let store = AchillesStore::new(dir.path().to_path_buf());
        let engagement = store
            .upsert_engagement(dir.path().to_str().unwrap())
            .await
            .unwrap();
        let first = store
            .create_assessment(&engagement, Some("sess-a"), "quick", "scan_cta", None)
            .await
            .unwrap();
        let hit = NewFinding {
            fingerprint: "sast|xss|app.js".into(),
            severity: Severity::High,
            confidence: "high".into(),
            category: "sast".into(),
            rule_id: "innerhtml".into(),
            title: "XSS sink".into(),
            description: "innerHTML".into(),
            path: Some("app.js".into()),
            line_start: Some(1),
            line_end: Some(1),
            cwe: vec!["CWE-79".into()],
            cve: vec![],
            evidence: serde_json::json!({"preview": "innerHTML"}),
        };
        store
            .upsert_finding(&engagement.id, &first.id, &hit)
            .await
            .unwrap();
        let second = store
            .create_assessment(&engagement, Some("sess-a"), "quick", "scan_cta", None)
            .await
            .unwrap();
        store
            .upsert_finding(&engagement.id, &second.id, &hit)
            .await
            .unwrap();

        assert!(store
            .list_findings(Some(&first.id), None, None)
            .await
            .unwrap()
            .is_empty());
        let history = store
            .list_findings_history(Some(&first.id), None, None)
            .await
            .unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].assessment_id, first.id);
        assert_eq!(history[0].last_seen_assessment_id, second.id);
        let latest = store
            .list_findings_history(Some(&second.id), None, None)
            .await
            .unwrap();
        assert_eq!(latest.len(), 1);
    }

    #[tokio::test]
    async fn lists_assessments_for_a_session() {
        let dir = tempfile::tempdir().unwrap();
        let store = AchillesStore::new(dir.path().to_path_buf());
        let engagement = store
            .upsert_engagement(dir.path().to_str().unwrap())
            .await
            .unwrap();
        store
            .create_assessment(&engagement, Some("sess-a"), "quick", "scan_cta", None)
            .await
            .unwrap();
        let later = store
            .create_assessment(&engagement, Some("sess-a"), "quick", "scan_cta", None)
            .await
            .unwrap();
        store
            .create_assessment(&engagement, Some("sess-b"), "quick", "scan_cta", None)
            .await
            .unwrap();

        let listed = store.list_assessments_for_session("sess-a").await.unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].id, later.id);
        assert!(listed
            .iter()
            .all(|row| row.session_id.as_deref() == Some("sess-a")));
        assert!(store
            .list_assessments_for_session("missing")
            .await
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn migrates_v1_assessment_rows() {
        let dir = tempfile::tempdir().unwrap();
        let achilles = dir.path().join(ACHILLES_FOLDER);
        std::fs::create_dir_all(&achilles).unwrap();
        let db_path = achilles.join(DB_NAME);
        let options = SqliteConnectOptions::new()
            .filename(&db_path)
            .create_if_missing(true);
        let pool = SqlitePoolOptions::new()
            .connect_with(options)
            .await
            .unwrap();
        for stmt in [
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY)",
            r#"CREATE TABLE engagements (
                id TEXT PRIMARY KEY,
                working_dir TEXT NOT NULL UNIQUE,
                display_name TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_assessment_at TEXT,
                status TEXT NOT NULL DEFAULT 'active'
            )"#,
            r#"CREATE TABLE assessments (
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
                trigger TEXT NOT NULL DEFAULT 'scan_cta'
            )"#,
            r#"CREATE TABLE findings (
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
            )"#,
            r#"CREATE TABLE engine_runs (
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
            )"#,
            "INSERT INTO schema_version (version) VALUES (1)",
            "INSERT INTO engagements (id, working_dir, display_name, created_at, updated_at, status) VALUES ('e1', 'C:/old', 'old', 't0', 't0', 'active')",
            r#"INSERT INTO assessments (
                id, engagement_id, mode, status, started_at, updated_at, phases_json, stats_json, trigger
            ) VALUES ('a1', 'e1', 'quick', 'completed', 't0', 't0', '{}', '{}', 'scan_cta')"#,
        ] {
            sqlx::query(stmt).execute(&pool).await.unwrap();
        }
        drop(pool);

        let store = AchillesStore::new(dir.path().to_path_buf());
        let loaded = store.get_assessment("a1").await.unwrap().unwrap();
        assert_eq!(loaded.id, "a1");
        assert!(loaded.content_fingerprint.is_none());
        assert!(loaded.head_git_sha.is_none());
        store
            .set_scan_identity("a1", Some("abc123"), "fp-1", "L")
            .await
            .unwrap();
        let updated = store.get_assessment("a1").await.unwrap().unwrap();
        assert_eq!(updated.head_git_sha.as_deref(), Some("abc123"));
        assert_eq!(updated.base_git_sha.as_deref(), Some("abc123"));
        assert_eq!(updated.content_fingerprint.as_deref(), Some("fp-1"));
        assert_eq!(updated.model_class.as_deref(), Some("L"));
    }

    #[tokio::test]
    async fn candidate_confirm_creates_finding() {
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
        let hit = NewFinding {
            fingerprint: "sast|eval|app.py".into(),
            severity: Severity::High,
            confidence: "medium".into(),
            category: "sast".into(),
            rule_id: "eval".into(),
            title: "eval".into(),
            description: "eval on input".into(),
            path: Some("app.py".into()),
            line_start: Some(3),
            line_end: Some(3),
            cwe: vec!["CWE-95".into()],
            cve: vec![],
            evidence: serde_json::json!({"preview": "eval(x)"}),
        };
        let candidate_id = store
            .upsert_candidate(&engagement.id, &assessment.id, "sast", &hit)
            .await
            .unwrap();
        let pending = store
            .list_candidates(&assessment.id, Some("pending"), Some("sast"))
            .await
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert!(store
            .list_findings(Some(&assessment.id), None, None)
            .await
            .unwrap()
            .is_empty());
        let finding_id = store.confirm_candidate(&candidate_id).await.unwrap();
        let findings = store
            .list_findings(Some(&assessment.id), None, None)
            .await
            .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, finding_id);
        let confirmed = store.get_candidate(&candidate_id).await.unwrap().unwrap();
        assert_eq!(confirmed.status, CandidateStatus::Confirmed);
        assert_eq!(confirmed.finding_id.as_deref(), Some(finding_id.as_str()));
    }

    #[tokio::test]
    async fn confirm_pending_candidates_promotes_all_engines() {
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
        let hit = NewFinding {
            fingerprint: "sast|eval|app.py".into(),
            severity: Severity::High,
            confidence: "medium".into(),
            category: "sast".into(),
            rule_id: "eval".into(),
            title: "eval".into(),
            description: "eval on input".into(),
            path: Some("app.py".into()),
            line_start: Some(3),
            line_end: Some(3),
            cwe: vec!["CWE-95".into()],
            cve: vec![],
            evidence: serde_json::json!({"preview": "eval(x)"}),
        };
        store
            .upsert_candidate(&engagement.id, &assessment.id, "sast", &hit)
            .await
            .unwrap();
        assert_eq!(
            store
                .confirm_pending_candidates(&assessment.id)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            store
                .count_pending_candidates(&assessment.id, "sast")
                .await
                .unwrap(),
            0
        );
        assert_eq!(
            store
                .list_findings(Some(&assessment.id), None, None)
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn work_unit_skips_matching_digest_and_reclaims_stale() {
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
        let decision = store
            .begin_work_unit(&assessment.id, "engine", "secrets", "dig-1", "run-a")
            .await
            .unwrap();
        assert_eq!(decision, WorkUnitDecision::Run);
        store
            .finish_work_unit(&assessment.id, "engine", "secrets", "done")
            .await
            .unwrap();
        let skip = store
            .begin_work_unit(&assessment.id, "engine", "secrets", "dig-1", "run-b")
            .await
            .unwrap();
        assert_eq!(skip, WorkUnitDecision::Skip);
        let rerun = store
            .begin_work_unit(&assessment.id, "engine", "secrets", "dig-2", "run-c")
            .await
            .unwrap();
        assert_eq!(rerun, WorkUnitDecision::Run);
        assert_eq!(store.reclaim_stale_units(&assessment.id).await.unwrap(), 1);
        let units = store.list_work_units(&assessment.id).await.unwrap();
        assert_eq!(units[0].status, "pending");
        assert!(units[0].locked_by_run_id.is_none());
    }
}
