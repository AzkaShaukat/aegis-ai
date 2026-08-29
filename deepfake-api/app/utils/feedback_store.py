"""
Phase 3: SQLite-backed feedback storage.
Persistent across restarts. Used for ML retraining data collection.
"""
from __future__ import annotations

import json
import logging
import os
import sqlite3
import time
import uuid
from typing import Optional

from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

DB_PATH = os.environ.get("FEEDBACK_DB_PATH", "data/feedback.db")


def _get_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    with _get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id          TEXT PRIMARY KEY,
                scan_id     TEXT NOT NULL,
                original    TEXT NOT NULL,
                corrected   TEXT NOT NULL,
                notes       TEXT,
                pipeline    TEXT,
                p_fake      REAL,
                timestamp   REAL NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_log (
                id          TEXT PRIMARY KEY,
                scan_date   TEXT NOT NULL,
                pipeline    TEXT NOT NULL,
                verdict     TEXT NOT NULL,
                risk_score  INTEGER NOT NULL,
                p_fake      REAL NOT NULL,
                elapsed_ms  REAL NOT NULL,
                cached      INTEGER NOT NULL,
                timestamp   REAL NOT NULL
            )
        """)
        conn.commit()
    logger.info(f"Feedback DB initialized: {DB_PATH}")


def save_feedback(
    scan_id: str,
    original_verdict: str,
    corrected_verdict: str,
    notes: Optional[str] = None,
    pipeline: Optional[str] = None,
    p_fake: Optional[float] = None,
) -> str:
    feedback_id = f"fb-{uuid.uuid4().hex[:8]}"
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO feedback VALUES (?,?,?,?,?,?,?,?)",
            (feedback_id, scan_id, original_verdict, corrected_verdict,
             notes, pipeline, p_fake, time.time()),
        )
        conn.commit()
    return feedback_id


def get_feedback_stats() -> dict:
    with _get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        corrections = conn.execute(
            "SELECT COUNT(*) FROM feedback WHERE original != corrected"
        ).fetchone()[0]
        fp = conn.execute(
            "SELECT COUNT(*) FROM feedback WHERE original='FAKE' AND corrected='real'"
        ).fetchone()[0]
        fn = conn.execute(
            "SELECT COUNT(*) FROM feedback WHERE original='REAL' AND corrected='fake'"
        ).fetchone()[0]
        recent = conn.execute(
            "SELECT * FROM feedback ORDER BY timestamp DESC LIMIT 5"
        ).fetchall()
    return {
        "total_feedback": total,
        "corrections": corrections,
        "false_positives": fp,
        "false_negatives": fn,
        "training_ready": total >= 50,
        "recent": [dict(r) for r in recent],
    }


def log_scan(
    scan_id: str, pipeline: str, verdict: str,
    risk_score: int, p_fake: float, elapsed_ms: float, cached: bool,
):
    """Log every scan for metrics aggregation."""
    try:
        with _get_conn() as conn:
            conn.execute(
                "INSERT OR IGNORE INTO scan_log VALUES (?,?,?,?,?,?,?,?,?)",
                (scan_id, time.strftime("%Y-%m-%d"), pipeline, verdict,
                 risk_score, p_fake, elapsed_ms, int(cached), time.time()),
            )
            conn.commit()
    except Exception as e:
        logger.warning(f"Scan log failed: {e}")


def get_metrics_summary() -> dict:
    with _get_conn() as conn:
        total = conn.execute("SELECT COUNT(*) FROM scan_log").fetchone()[0]
        cached = conn.execute("SELECT COUNT(*) FROM scan_log WHERE cached=1").fetchone()[0]
        avg_ms = conn.execute("SELECT AVG(elapsed_ms) FROM scan_log WHERE cached=0").fetchone()[0]
        dist = conn.execute(
            "SELECT verdict, COUNT(*) as cnt FROM scan_log GROUP BY verdict"
        ).fetchall()
        by_day = conn.execute(
            "SELECT scan_date, COUNT(*) as cnt FROM scan_log GROUP BY scan_date ORDER BY scan_date DESC LIMIT 7"
        ).fetchall()
        pipeline_dist = conn.execute(
            "SELECT pipeline, COUNT(*) as cnt FROM scan_log GROUP BY pipeline"
        ).fetchall()
    return {
        "total_scans": total,
        "cache_hits": cached,
        "cache_misses": total - cached,
        "cache_hit_rate_pct": round(cached / total * 100, 1) if total > 0 else 0.0,
        "avg_scan_time_ms": round(avg_ms or 0, 1),
        "verdict_distribution": {row[0]: row[1] for row in dist},
        "pipeline_distribution": {row[0]: row[1] for row in pipeline_dist},
        "daily_scans_last_7_days": {row[0]: row[1] for row in by_day},
    }
