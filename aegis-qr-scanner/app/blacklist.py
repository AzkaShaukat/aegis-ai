"""
Feature 1.6 - Payload Hash Blacklist (SQLite)
Stores SHA-256 hashes of confirmed-malicious QR payloads.
Instant detection — zero network calls, zero latency.
"""
import sqlite3
import hashlib
import os
from datetime import datetime
from typing import Optional
from app.logger import log

DB_PATH = os.getenv("BLACKLIST_DB_PATH", "/code/app/blacklist.db")

SEED_ENTRIES = [
    # Format: (payload_preview, threat_type, source)
    # These are well-known test/demo payloads — add real ones as discovered
    ("http://malware.testing.google.test/testing/malware/", "malware", "google_safe_browsing_test"),
    ("https://phishing.example.test/login/steal", "phishing", "aegis_seed"),
]

def _get_connection() -> sqlite3.Connection:
    """Returns a thread-safe SQLite connection."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_blacklist_db():
    """
    Creates the database tables if they don't exist.
    Call this once at application startup.
    """
    try:
        conn = _get_connection()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                hash            TEXT    UNIQUE NOT NULL,
                payload_preview TEXT    NOT NULL,
                threat_type     TEXT    NOT NULL,
                date_added      TEXT    NOT NULL,
                source          TEXT    DEFAULT 'manual',
                times_blocked   INTEGER DEFAULT 0,
                is_active       INTEGER DEFAULT 1,
                notes           TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_hash ON blacklist(hash);
            CREATE INDEX IF NOT EXISTS idx_threat ON blacklist(threat_type);
            CREATE INDEX IF NOT EXISTS idx_active ON blacklist(is_active);

            CREATE TABLE IF NOT EXISTS scan_cache (
                cache_key   TEXT PRIMARY KEY,
                result_json TEXT NOT NULL,
                cached_at   TEXT NOT NULL,
                expires_at  TEXT NOT NULL
            );
        """)
        conn.commit()

        # Seed with known test payloads
        for preview, threat, source in SEED_ENTRIES:
            _seed_entry(conn, preview, threat, source)

        conn.close()
        log.info("[Blacklist] Database initialised successfully")
    except Exception as e:
        log.error(f"[Blacklist] DB init failed: {e}")

def _seed_entry(conn, payload: str, threat_type: str, source: str):
    """Add a seed entry without raising if it already exists."""
    try:
        payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        preview = payload[:80] + "..." if len(payload) > 80 else payload
        conn.execute("""
            INSERT OR IGNORE INTO blacklist (hash, payload_preview, threat_type, date_added, source)
            VALUES (?, ?, ?, ?, ?)
        """, (payload_hash, preview, threat_type, datetime.utcnow().isoformat(), source))
        conn.commit()
    except Exception:
        pass

def check_blacklist(payload: str) -> dict:
    """
    Checks if a payload (exact string) is in the blacklist.
    Uses SHA-256 so actual malicious content is never stored.

    Returns:
    {
        "blacklisted": bool,
        "hash": str,
        "threat_type": str or None,
        "date_added": str or None,
        "times_blocked": int,
        "source": str or None
    }
    """
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()

    try:
        conn = _get_connection()
        row = conn.execute("""
            SELECT threat_type, date_added, times_blocked, source, notes
            FROM blacklist
            WHERE hash = ? AND is_active = 1
        """, (payload_hash,)).fetchone()

        if row:
            # Increment block counter
            conn.execute(
                "UPDATE blacklist SET times_blocked = times_blocked + 1 WHERE hash = ?",
                (payload_hash,)
            )
            conn.commit()
            conn.close()

            log.warning(
                f"[Blacklist] 🚨 BLACKLISTED PAYLOAD DETECTED — "
                f"type: {row['threat_type']}, blocked {row['times_blocked']+1}x, "
                f"source: {row['source']}"
            )
            return {
                "blacklisted":    True,
                "hash":           payload_hash,
                "threat_type":    row["threat_type"],
                "date_added":     row["date_added"],
                "times_blocked":  row["times_blocked"] + 1,
                "source":         row["source"],
                "notes":          row["notes"],
                "alert":          f"🚨 Known {row['threat_type']} payload — blocked immediately"
            }

        conn.close()
    except Exception as e:
        log.error(f"[Blacklist] Check failed: {e}")

    return {
        "blacklisted":   False,
        "hash":          payload_hash,
        "threat_type":   None,
        "date_added":    None,
        "times_blocked": 0,
        "source":        None
    }

def add_to_blacklist(
    payload: str,
    threat_type: str,
    source: str = "user_report",
    notes: Optional[str] = None
) -> dict:
    """
    Adds a confirmed malicious payload to the blacklist.
    Stores only the SHA-256 hash — never the raw payload.

    threat_type options: phishing, malware, smishing, vishing,
                          crypto_scam, credential_harvest, spam, other
    """
    payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    preview = payload[:80] + "..." if len(payload) > 80 else payload

    try:
        conn = _get_connection()
        conn.execute("""
            INSERT OR REPLACE INTO blacklist
                (hash, payload_preview, threat_type, date_added, source, notes, times_blocked, is_active)
            VALUES (?, ?, ?, ?, ?, ?, 0, 1)
        """, (payload_hash, preview, threat_type, datetime.utcnow().isoformat(), source, notes))
        conn.commit()
        conn.close()

        log.info(f"[Blacklist] Added: {payload_hash[:16]}... type={threat_type} source={source}")
        return {
            "added":       True,
            "hash":        payload_hash,
            "threat_type": threat_type,
            "preview":     preview
        }
    except Exception as e:
        log.error(f"[Blacklist] Add failed: {e}")
        return {"added": False, "error": str(e)}

def remove_from_blacklist(payload_hash: str) -> dict:
    """Deactivates a blacklist entry (soft delete)."""
    try:
        conn = _get_connection()
        conn.execute("UPDATE blacklist SET is_active = 0 WHERE hash = ?", (payload_hash,))
        conn.commit()
        conn.close()
        return {"removed": True, "hash": payload_hash}
    except Exception as e:
        return {"removed": False, "error": str(e)}

def get_blacklist_stats() -> dict:
    """Returns statistics about the blacklist database."""
    try:
        conn = _get_connection()
        total = conn.execute("SELECT COUNT(*) FROM blacklist WHERE is_active = 1").fetchone()[0]
        by_type = conn.execute("""
            SELECT threat_type, COUNT(*) as count, SUM(times_blocked) as total_blocked
            FROM blacklist WHERE is_active = 1
            GROUP BY threat_type ORDER BY count DESC
        """).fetchall()
        most_blocked = conn.execute("""
            SELECT payload_preview, threat_type, times_blocked
            FROM blacklist WHERE is_active = 1
            ORDER BY times_blocked DESC LIMIT 5
        """).fetchall()
        conn.close()

        return {
            "total_entries":    total,
            "by_threat_type":   [dict(r) for r in by_type],
            "most_blocked":     [dict(r) for r in most_blocked]
        }
    except Exception as e:
        log.error(f"[Blacklist] Stats failed: {e}")
        return {"error": str(e)}
