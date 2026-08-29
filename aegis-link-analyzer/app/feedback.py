"""
Feature 12 — Feedback Loop
Aegis Link Analyzer | Phase 3

Allows users to correct scan results (false positives / false negatives).
Stored in local SQLite database — zero setup, zero cost, works inside Docker.
Data persists across container restarts via a Docker volume.

This feedback data is the foundation for Phase 4 ML model training.
Every correction becomes a labeled training example.
"""

import aiosqlite
import os
from datetime import datetime
from typing import Optional, List, Dict

DB_PATH = os.getenv("FEEDBACK_DB_PATH", "/code/app/feedback.db")


# ─────────────────────────────────────────────
# DATABASE INITIALIZATION
# ─────────────────────────────────────────────

async def init_feedback_db():
    """
    Creates the feedback database and table on first startup.
    Safe to call multiple times — uses CREATE TABLE IF NOT EXISTS.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS feedback (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id         TEXT NOT NULL,
                url             TEXT NOT NULL,
                original_risk   TEXT NOT NULL,
                corrected_risk  TEXT NOT NULL,
                feedback_type   TEXT NOT NULL,
                user_note       TEXT,
                submitted_at    TEXT NOT NULL,
                confidence_score REAL,
                total_flags     INTEGER
            )
        """)

        # Separate table to store which flags user said were false
        await db.execute("""
            CREATE TABLE IF NOT EXISTS false_flags (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                feedback_id INTEGER NOT NULL,
                flag_text   TEXT NOT NULL,
                FOREIGN KEY (feedback_id) REFERENCES feedback(id)
            )
        """)

        await db.commit()


# ─────────────────────────────────────────────
# SAVE FEEDBACK
# ─────────────────────────────────────────────

async def save_feedback(
    scan_id: str,
    url: str,
    original_risk: str,
    corrected_risk: str,
    feedback_type: str,
    user_note: Optional[str] = None,
    confidence_score: Optional[float] = None,
    total_flags: Optional[int] = None,
    false_flags: Optional[List[str]] = None
) -> Dict:
    """
    Saves a user feedback entry to the SQLite database.

    Args:
        scan_id:         The scan_id from the original scan result
        url:             The URL that was scanned
        original_risk:   What the system said ("High Risk", "Safe", etc.)
        corrected_risk:  What the user says it should be
        feedback_type:   "false_positive" | "false_negative" | "wrong_level" | "correct"
        user_note:       Optional free-text explanation from user
        confidence_score: Original confidence score (for ML training context)
        total_flags:     Number of flags in original result
        false_flags:     List of flags the user says were incorrect

    Returns:
        dict with feedback_id and status
    """
    submitted_at = datetime.utcnow().isoformat()

    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute(
            """
            INSERT INTO feedback
                (scan_id, url, original_risk, corrected_risk, feedback_type,
                 user_note, submitted_at, confidence_score, total_flags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id, url, original_risk, corrected_risk, feedback_type,
                user_note, submitted_at, confidence_score, total_flags
            )
        )
        feedback_id = cursor.lastrowid

        # Save any specifically-flagged false flags
        if false_flags:
            for flag_text in false_flags:
                await db.execute(
                    "INSERT INTO false_flags (feedback_id, flag_text) VALUES (?, ?)",
                    (feedback_id, flag_text)
                )

        await db.commit()

    return {
        "feedback_id": feedback_id,
        "status": "saved",
        "message": (
            "Thank you! Your feedback helps improve detection accuracy. "
            "It will be used to retrain the local ML classifier in Phase 4."
        ),
        "submitted_at": submitted_at
    }


# ─────────────────────────────────────────────
# GET FEEDBACK STATS
# ─────────────────────────────────────────────

async def get_feedback_stats() -> Dict:
    """
    Returns summary statistics from the feedback database.
    Useful for the metrics endpoint and ML training decisions.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        # Total feedback count
        cursor = await db.execute("SELECT COUNT(*) as total FROM feedback")
        row = await cursor.fetchone()
        total = row["total"] if row else 0

        # Breakdown by type
        cursor = await db.execute(
            "SELECT feedback_type, COUNT(*) as count FROM feedback GROUP BY feedback_type"
        )
        type_breakdown = {row["feedback_type"]: row["count"] async for row in cursor}

        # Most recent entries
        cursor = await db.execute(
            """
            SELECT url, original_risk, corrected_risk, feedback_type, submitted_at
            FROM feedback
            ORDER BY submitted_at DESC
            LIMIT 10
            """
        )
        recent = [dict(row) async for row in cursor]

        # False positive rate (system said dangerous, user said safe)
        fp_count = type_breakdown.get("false_positive", 0)
        fn_count = type_breakdown.get("false_negative", 0)

    return {
        "total_feedback": total,
        "breakdown_by_type": type_breakdown,
        "false_positives": fp_count,
        "false_negatives": fn_count,
        "recent_feedback": recent,
        "training_ready": total >= 50  # Suggest ML retraining when we have 50+ samples
    }


async def get_all_feedback_for_training() -> List[Dict]:
    """
    Returns all feedback records formatted for ML training.
    Used by Phase 4 ML pipeline.
    Each record includes URL + correction label for supervised learning.
    """
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute(
            """
            SELECT f.*, GROUP_CONCAT(ff.flag_text, '|||') as false_flag_texts
            FROM feedback f
            LEFT JOIN false_flags ff ON ff.feedback_id = f.id
            GROUP BY f.id
            ORDER BY f.submitted_at DESC
            """
        )
        rows = [dict(row) async for row in cursor]

    # Parse the concatenated false flags back into lists
    for row in rows:
        raw = row.get("false_flag_texts") or ""
        row["false_flags"] = [f for f in raw.split("|||") if f] if raw else []

    return rows
