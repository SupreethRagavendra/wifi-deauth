"""
prevention-engine/db.py
MySQL helpers — connects to Aiven Cloud DB using config.yml credentials.
Includes retry logic for transient DNS/network failures.

Tables used:
  - prevention_session        (engine sessions)
  - prevention_events         (one row per processed detection event)
  - honeypot_log              (honeypot start/stop events)
"""

import mysql.connector
import os
import time
import uuid
import yaml

# ── Load config ──────────────────────────────────────────────────────────────
_CFG_PATH = os.path.join(os.path.dirname(__file__), "config.yml")

def _load_config():
    """Load database config from config.yml, with env-var fallbacks."""
    try:
        with open(_CFG_PATH) as f:
            cfg = yaml.safe_load(f)
        return cfg.get("database", {})
    except Exception:
        return {}

_db_cfg = _load_config()

DB_CONFIG = {
    "host":               os.getenv("DB_HOST",     _db_cfg.get("host", "mysql-2a681751-supreethvennila69-f64d.e.aivencloud.com")),
    "port":               int(os.getenv("DB_PORT", str(_db_cfg.get("port", 23766)))),
    "user":               os.getenv("DB_USERNAME", _db_cfg.get("user", "avnadmin")),
    "password":           os.getenv("DB_PASSWORD", _db_cfg.get("password", "<YOUR_DB_PASSWORD>")),
    "database":           os.getenv("DB_NAME",     _db_cfg.get("name", "wifi_deauth")),
    "ssl_ca":             None,
    "ssl_disabled":       _db_cfg.get("ssl_disabled", False),
    "connection_timeout": _db_cfg.get("connection_timeout", 10),
}

MAX_RETRIES = _db_cfg.get("max_retries", 3)
RETRY_DELAY = _db_cfg.get("retry_delay", 2)


# ── Connection helper ────────────────────────────────────────────────────────
def _conn():
    """Open a connection with retry for transient DNS/network failures."""
    last_err = None
    for attempt in range(MAX_RETRIES):
        try:
            return mysql.connector.connect(**DB_CONFIG)
        except Exception as e:
            last_err = e
            if attempt < MAX_RETRIES - 1:
                time.sleep(RETRY_DELAY)
    raise last_err


# ── Schema init ──────────────────────────────────────────────────────────────
def init_schema():
    """Create tables if they don't exist (runs on startup)."""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path) as f:
        raw = f.read()

    # Strip pure comment lines before splitting
    lines = [ln for ln in raw.splitlines() if not ln.strip().startswith("--")]
    sql = "\n".join(lines)

    statements = [s.strip() for s in sql.split(";") if s.strip()]
    conn = _conn()
    cur = conn.cursor()
    for stmt in statements:
        try:
            cur.execute(stmt)
        except Exception as e:
            # Skip errors for already-existing objects
            print(f"  ⚠️  Schema stmt skipped: {str(e)[:80]}")
    conn.commit()
    cur.close()
    conn.close()
    print("✅ DB schema initialised")


# ── Session management ───────────────────────────────────────────────────────
def start_session() -> int:
    """Insert a new prevention_session row, return its id."""
    conn = _conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO prevention_session (active_levels, status) VALUES ('L1+L2+L3+L4', 'running')"
    )
    sid = cur.lastrowid
    conn.commit()
    cur.close()
    conn.close()
    return sid


def end_session(session_id: int):
    """Mark a session as stopped."""
    conn = _conn()
    cur = conn.cursor()
    cur.execute(
        "UPDATE prevention_session SET status='stopped', ended_at=NOW() WHERE id=%s",
        (session_id,)
    )
    conn.commit()
    cur.close()
    conn.close()


# ── Prevention events ────────────────────────────────────────────────────────
def insert_event(
    session_id,
    detection_event_id,
    attacker_mac,
    victim_mac,
    confidence,
    baseline_ms,
    optimized_ms,
    improvement_pct,
    level1_fired,
    level2_fired,
    level3_fired,
    level4_fired,
    components_fired,
    honeypot_active,
    forensic_report_path,
    status,
    error_msg=None,
) -> str:
    """Insert a prevention event row. Returns the generated UUID."""
    event_id = str(uuid.uuid4())
    conn = _conn()
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO prevention_events
          (id, detection_event_id, session_id, confidence,
           attacker_mac, victim_mac,
           baseline_latency_ms, optimized_latency_ms, improvement_pct,
           level1_fired, level2_fired, level3_fired, level4_fired,
           components_fired, honeypot_active, forensic_report_path,
           status, error_msg)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    """, (
        event_id, detection_event_id, session_id, confidence,
        attacker_mac, victim_mac,
        baseline_ms, optimized_ms, improvement_pct,
        level1_fired, level2_fired, level3_fired, level4_fired,
        components_fired, honeypot_active, forensic_report_path,
        status, error_msg,
    ))
    conn.commit()
    cur.close()
    conn.close()
    return event_id


# ── Query helpers ────────────────────────────────────────────────────────────
def get_events(limit=50):
    """Return most recent prevention events as list of dicts."""
    conn = _conn()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT id, detection_event_id, session_id, confidence,
               attacker_mac, victim_mac,
               baseline_latency_ms, optimized_latency_ms, improvement_pct,
               level1_fired, level2_fired, level3_fired, level4_fired,
               components_fired, honeypot_active, forensic_report_path,
               status, error_msg, created_at
        FROM prevention_events
        ORDER BY created_at DESC
        LIMIT %s
    """, (limit,))
    rows = cur.fetchall()
    cur.close()
    conn.close()
    # Convert datetime to ISO string for JSON serialisation
    for r in rows:
        if r.get("created_at"):
            r["created_at"] = r["created_at"].isoformat()
        # Convert booleans (MySQL returns 0/1)
        for key in ("level1_fired", "level2_fired", "level3_fired", "level4_fired", "honeypot_active"):
            r[key] = bool(r.get(key))
    return rows


def get_stats():
    """Return aggregated stats for the dashboard KPIs."""
    conn = _conn()
    cur = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT
            COUNT(*)                            AS total,
            AVG(baseline_latency_ms)            AS avg_baseline_ms,
            AVG(optimized_latency_ms)           AS avg_optimized_ms,
            AVG(improvement_pct)                AS avg_improvement_pct,
            MIN(optimized_latency_ms)           AS best_ms,
            COUNT(CASE WHEN DATE(created_at)=CURDATE() THEN 1 END) AS events_today,
            SUM(level1_fired)  AS l1_count,
            SUM(level2_fired)  AS l2_count,
            SUM(level3_fired)  AS l3_count,
            SUM(level4_fired)  AS l4_count,
            SUM(honeypot_active) AS honeypot_count
        FROM prevention_events
        WHERE status IN ('measured', 'applied')
    """)
    overall = cur.fetchone()

    cur.close()
    conn.close()

    return {
        "total":               overall["total"] or 0,
        "avg_baseline_ms":     round(float(overall["avg_baseline_ms"] or 0), 1),
        "avg_optimized_ms":    round(float(overall["avg_optimized_ms"] or 0), 1),
        "avg_improvement_pct": round(float(overall["avg_improvement_pct"] or 0), 1),
        "best_ms":             round(float(overall["best_ms"] or 0), 1),
        "events_today":        overall["events_today"] or 0,
        "l1_count":            int(overall["l1_count"] or 0),
        "l2_count":            int(overall["l2_count"] or 0),
        "l3_count":            int(overall["l3_count"] or 0),
        "l4_count":            int(overall["l4_count"] or 0),
        "honeypot_count":      int(overall["honeypot_count"] or 0),
    }


def clear_events():
    """Delete all rows from prevention_events and reset sessions."""
    conn = _conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM prevention_events")
    cur.execute("DELETE FROM prevention_session")
    cur.execute("DELETE FROM honeypot_log")
    conn.commit()
    cur.close()
    conn.close()


# ── Honeypot log ─────────────────────────────────────────────────────────────
def log_honeypot(action: str, fake_ap_count: int = 150, fake_client_count: int = 150):
    """Log a honeypot start/stop event."""
    conn = _conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO honeypot_log (action, fake_ap_count, fake_client_count) VALUES (%s, %s, %s)",
        (action, fake_ap_count, fake_client_count)
    )
    conn.commit()
    cur.close()
    conn.close()
