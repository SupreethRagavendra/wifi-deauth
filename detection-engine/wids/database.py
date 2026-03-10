"""
WIDS Database Layer — MySQL Connection Pool and CRUD Helpers

Provides WIDSDatabase class wrapping mysql-connector-python with a pooled
connection, plus insert/query/update helpers for every WIDS table.
"""

import json
import logging
import time
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import Any, Dict, List, Optional, Tuple

try:
    import mysql.connector
    from mysql.connector import pooling, Error as MySQLError
except ImportError:
    raise ImportError(
        "mysql-connector-python is required. Install with: "
        "pip install mysql-connector-python"
    )

logger = logging.getLogger("WIDS.Database")


class WIDSDatabase:
    """
    MySQL connection pool and CRUD helpers for all WIDS tables.

    Usage:
        db = WIDSDatabase(host="localhost", database="wifi_security")
        db.insert_event({...})
        events = db.get_active_events()
        db.close()
    """

    def __init__(
        self,
        host: str = "localhost",
        port: int = 3306,
        user: str = "root",
        password: str = "",
        database: str = "wifi_security",
        pool_size: int = 5,
        pool_name: str = "wids_pool",
    ):
        """Initialize connection pool."""
        self.db_config = {
            "host": host,
            "port": port,
            "user": user,
            "password": password,
            "database": database,
        }
        try:
            self.pool = pooling.MySQLConnectionPool(
                pool_name=pool_name,
                pool_size=pool_size,
                pool_reset_session=True,
                **self.db_config,
            )
            logger.info(
                "Database pool '%s' created (%d connections) → %s@%s:%d/%s",
                pool_name, pool_size, user, host, port, database,
            )
        except MySQLError as e:
            logger.error("Failed to create connection pool: %s", e)
            raise

    @contextmanager
    def _get_connection(self):
        """Context manager yielding a pooled connection + cursor."""
        conn = None
        try:
            conn = self.pool.get_connection()
            cursor = conn.cursor(dictionary=True)
            yield conn, cursor
            conn.commit()
        except MySQLError as e:
            if conn:
                conn.rollback()
            logger.error("Database error: %s", e)
            raise
        finally:
            if conn and conn.is_connected():
                cursor.close()
                conn.close()

    def close(self):
        """Close all pooled connections (no-op for mysql.connector pools)."""
        logger.info("Database pool shutdown requested")

    # ================================================================
    # wids_events
    # ================================================================

    def insert_event(self, event: Dict[str, Any]) -> int:
        """
        Insert a detection event into wids_events.

        Args:
            event: dict with keys matching column names. Missing keys get
                   defaults from the schema.

        Returns:
            The auto-incremented event_id.
        """
        sql = """
            INSERT INTO wids_events (
                timestamp, bssid, source_mac, victim_mac, channel,
                reason_code, frame_count, max_rssi, is_spoofed,
                rssi_deviation, real_attacker_mac, attacker_confidence,
                detection_methods, sequence_gap, iat_analysis,
                prevention_level, is_active
            ) VALUES (
                %(timestamp)s, %(bssid)s, %(source_mac)s, %(victim_mac)s,
                %(channel)s, %(reason_code)s, %(frame_count)s, %(max_rssi)s,
                %(is_spoofed)s, %(rssi_deviation)s, %(real_attacker_mac)s,
                %(attacker_confidence)s, %(detection_methods)s,
                %(sequence_gap)s, %(iat_analysis)s, %(prevention_level)s,
                %(is_active)s
            )
        """
        # Fill defaults for missing keys
        defaults = {
            "timestamp": datetime.now(),
            "bssid": "",
            "source_mac": "",
            "victim_mac": None,
            "channel": None,
            "reason_code": None,
            "frame_count": 0,
            "max_rssi": None,
            "is_spoofed": False,
            "rssi_deviation": None,
            "real_attacker_mac": None,
            "attacker_confidence": None,
            "detection_methods": None,
            "sequence_gap": None,
            "iat_analysis": None,
            "prevention_level": 0,
            "is_active": True,
        }
        params = {**defaults, **event}

        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, params)
            event_id = cursor.lastrowid
            logger.debug("Inserted event %d: src=%s bssid=%s",
                         event_id, params["source_mac"], params["bssid"])
            return event_id

    def get_active_events(self, limit: int = 100) -> List[Dict]:
        """Return currently active events, newest first."""
        sql = """
            SELECT * FROM wids_events
            WHERE is_active = TRUE
            ORDER BY timestamp DESC
            LIMIT %s
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, (limit,))
            return cursor.fetchall()

    def get_recent_events(
        self, source_mac: str, window_seconds: int = 5
    ) -> List[Dict]:
        """Get events from a specific source MAC within the time window."""
        sql = """
            SELECT * FROM wids_events
            WHERE source_mac = %s
              AND timestamp >= NOW(6) - INTERVAL %s SECOND
            ORDER BY timestamp DESC
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, (source_mac, window_seconds))
            return cursor.fetchall()

    def count_frames_in_window(
        self, source_mac: str, window_seconds: int = 5
    ) -> int:
        """Count total frame_count for a source MAC in the sliding window."""
        sql = """
            SELECT COALESCE(SUM(frame_count), 0) AS total
            FROM wids_events
            WHERE source_mac = %s
              AND timestamp >= NOW(6) - INTERVAL %s SECOND
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, (source_mac, window_seconds))
            row = cursor.fetchone()
            return row["total"] if row else 0

    def expire_old_events(self, max_age_seconds: int = 60) -> int:
        """Mark events older than max_age_seconds as inactive."""
        sql = """
            UPDATE wids_events
            SET is_active = FALSE
            WHERE is_active = TRUE
              AND timestamp < NOW(6) - INTERVAL %s SECOND
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, (max_age_seconds,))
            count = cursor.rowcount
            if count > 0:
                logger.info("Expired %d events older than %ds", count, max_age_seconds)
            return count

    # ================================================================
    # wids_fingerprints
    # ================================================================

    def upsert_fingerprint(self, fp: Dict[str, Any]) -> int:
        """
        Insert or update an RF fingerprint for a MAC address.

        If the MAC already exists, update the signature fields.
        Returns the fingerprint_id.
        """
        # Check if MAC already has a fingerprint
        check_sql = """
            SELECT fingerprint_id FROM wids_fingerprints
            WHERE mac_address = %s
            LIMIT 1
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(check_sql, (fp["mac_address"],))
            existing = cursor.fetchone()

            if existing:
                update_sql = """
                    UPDATE wids_fingerprints SET
                        rssi_vector = %s,
                        rssi_mean = %s,
                        rssi_stdev = %s,
                        phase_offset = %s,
                        clock_skew = %s,
                        last_seen = NOW(6),
                        packet_count = %s,
                        frame_types = %s,
                        spatial_coordinates = %s
                    WHERE fingerprint_id = %s
                """
                cursor.execute(update_sql, (
                    json.dumps(fp.get("rssi_vector", [])),
                    fp.get("rssi_mean"),
                    fp.get("rssi_stdev"),
                    fp.get("phase_offset"),
                    fp.get("clock_skew"),
                    fp.get("packet_count", 0),
                    json.dumps(fp.get("frame_types", [])),
                    json.dumps(fp.get("spatial_coordinates")),
                    existing["fingerprint_id"],
                ))
                return existing["fingerprint_id"]
            else:
                insert_sql = """
                    INSERT INTO wids_fingerprints (
                        mac_address, rssi_vector, rssi_mean, rssi_stdev,
                        phase_offset, clock_skew, first_seen, last_seen,
                        packet_count, frame_types, spatial_coordinates
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, NOW(6), NOW(6),
                        %s, %s, %s
                    )
                """
                cursor.execute(insert_sql, (
                    fp["mac_address"],
                    json.dumps(fp.get("rssi_vector", [])),
                    fp.get("rssi_mean"),
                    fp.get("rssi_stdev"),
                    fp.get("phase_offset"),
                    fp.get("clock_skew"),
                    fp.get("packet_count", 0),
                    json.dumps(fp.get("frame_types", [])),
                    json.dumps(fp.get("spatial_coordinates")),
                ))
                return cursor.lastrowid

    def get_fingerprint(self, mac_address: str) -> Optional[Dict]:
        """Get the RF fingerprint for a MAC."""
        sql = """
            SELECT * FROM wids_fingerprints
            WHERE mac_address = %s
            LIMIT 1
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, (mac_address,))
            row = cursor.fetchone()
            if row:
                # Deserialize JSON columns
                for col in ("rssi_vector", "frame_types", "spatial_coordinates"):
                    if row.get(col) and isinstance(row[col], str):
                        try:
                            row[col] = json.loads(row[col])
                        except (json.JSONDecodeError, TypeError):
                            pass
            return row

    def get_all_fingerprints(self) -> List[Dict]:
        """Get all RF fingerprints."""
        sql = "SELECT * FROM wids_fingerprints ORDER BY last_seen DESC"
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql)
            rows = cursor.fetchall()
            for row in rows:
                for col in ("rssi_vector", "frame_types", "spatial_coordinates"):
                    if row.get(col) and isinstance(row[col], str):
                        try:
                            row[col] = json.loads(row[col])
                        except (json.JSONDecodeError, TypeError):
                            pass
            return rows

    # ================================================================
    # wids_blocked_devices
    # ================================================================

    def insert_block(self, block: Dict[str, Any]) -> int:
        """
        Insert a MAC block entry. Uses INSERT ... ON DUPLICATE KEY UPDATE
        to handle re-blocking an already-blocked MAC.
        """
        sql = """
            INSERT INTO wids_blocked_devices (
                mac_address, block_timestamp, trigger_event_id, block_type,
                expires_at, block_method, is_real_attacker, confidence, status
            ) VALUES (
                %(mac_address)s, NOW(6), %(trigger_event_id)s, %(block_type)s,
                %(expires_at)s, %(block_method)s, %(is_real_attacker)s,
                %(confidence)s, 'active'
            )
            ON DUPLICATE KEY UPDATE
                block_timestamp = NOW(6),
                trigger_event_id = VALUES(trigger_event_id),
                block_type = VALUES(block_type),
                expires_at = VALUES(expires_at),
                block_method = VALUES(block_method),
                is_real_attacker = VALUES(is_real_attacker),
                confidence = VALUES(confidence),
                status = 'active',
                released_at = NULL,
                release_reason = NULL
        """
        defaults = {
            "mac_address": "",
            "trigger_event_id": None,
            "block_type": "temporary",
            "expires_at": None,
            "block_method": "ebtables",
            "is_real_attacker": False,
            "confidence": 0.0,
        }
        params = {**defaults, **block}

        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, params)
            block_id = cursor.lastrowid
            logger.info("Blocked MAC %s (type=%s, method=%s)",
                        params["mac_address"], params["block_type"],
                        params["block_method"])
            return block_id

    def release_block(self, mac_address: str, reason: str = "manual") -> bool:
        """Release a block on a MAC address."""
        sql = """
            UPDATE wids_blocked_devices
            SET status = 'released',
                released_at = NOW(6),
                release_reason = %s
            WHERE mac_address = %s AND status = 'active'
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, (reason, mac_address))
            released = cursor.rowcount > 0
            if released:
                logger.info("Released block on %s: %s", mac_address, reason)
            return released

    def get_active_blocks(self) -> List[Dict]:
        """Get all currently active blocks."""
        sql = """
            SELECT * FROM wids_blocked_devices
            WHERE status = 'active'
            ORDER BY block_timestamp DESC
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql)
            return cursor.fetchall()

    def is_blocked(self, mac_address: str) -> bool:
        """Check if a MAC is currently blocked."""
        sql = """
            SELECT 1 FROM wids_blocked_devices
            WHERE mac_address = %s AND status = 'active'
            LIMIT 1
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, (mac_address,))
            return cursor.fetchone() is not None

    def cleanup_expired_blocks(self) -> int:
        """Mark expired temporary blocks as 'expired'."""
        sql = """
            UPDATE wids_blocked_devices
            SET status = 'expired',
                released_at = NOW(6),
                release_reason = 'auto-expired'
            WHERE status = 'active'
              AND block_type = 'temporary'
              AND expires_at IS NOT NULL
              AND expires_at <= NOW()
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql)
            count = cursor.rowcount
            if count > 0:
                logger.info("Expired %d temporary blocks", count)
            return count

    # ================================================================
    # wids_audit_log
    # ================================================================

    def insert_audit_log(self, log_entry: Dict[str, Any]) -> int:
        """Log a prevention action to the audit trail."""
        sql = """
            INSERT INTO wids_audit_log (
                timestamp, event_id, action_type, target_mac,
                action_details, success, error_message
            ) VALUES (
                NOW(6), %(event_id)s, %(action_type)s, %(target_mac)s,
                %(action_details)s, %(success)s, %(error_message)s
            )
        """
        defaults = {
            "event_id": None,
            "action_type": "unknown",
            "target_mac": None,
            "action_details": None,
            "success": True,
            "error_message": None,
        }
        params = {**defaults, **log_entry}

        # Serialize action_details if it's a dict
        if isinstance(params.get("action_details"), dict):
            params["action_details"] = json.dumps(params["action_details"])

        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, params)
            action_id = cursor.lastrowid
            logger.debug("Audit log #%d: %s on %s",
                         action_id, params["action_type"], params["target_mac"])
            return action_id

    def get_recent_audit_logs(
        self, limit: int = 50, since_minutes: int = 60
    ) -> List[Dict]:
        """Get recent audit log entries."""
        sql = """
            SELECT * FROM wids_audit_log
            WHERE timestamp >= NOW(6) - INTERVAL %s MINUTE
            ORDER BY timestamp DESC
            LIMIT %s
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, (since_minutes, limit))
            rows = cursor.fetchall()
            for row in rows:
                if row.get("action_details") and isinstance(row["action_details"], str):
                    try:
                        row["action_details"] = json.loads(row["action_details"])
                    except (json.JSONDecodeError, TypeError):
                        pass
            return rows

    # ================================================================
    # ap_baseline
    # ================================================================

    def get_baseline(self, ap_mac: str) -> Optional[Dict]:
        """Get the RSSI baseline for an AP."""
        sql = """
            SELECT * FROM ap_baseline
            WHERE ap_mac = %s
            LIMIT 1
        """
        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, (ap_mac,))
            row = cursor.fetchone()
            if row and row.get("samples_raw") and isinstance(row["samples_raw"], str):
                try:
                    row["samples_raw"] = json.loads(row["samples_raw"])
                except (json.JSONDecodeError, TypeError):
                    pass
            return row

    def set_baseline(self, baseline: Dict[str, Any]) -> int:
        """
        Insert or replace the RSSI baseline for an AP.

        Args:
            baseline: dict with keys: ap_mac, rssi_mean, rssi_stdev,
                      rssi_min, rssi_max, sample_count, samples_raw
        Returns:
            The baseline_id.
        """
        sql = """
            INSERT INTO ap_baseline (
                ap_mac, rssi_mean, rssi_stdev, rssi_min, rssi_max,
                sample_count, established_at, samples_raw
            ) VALUES (
                %(ap_mac)s, %(rssi_mean)s, %(rssi_stdev)s,
                %(rssi_min)s, %(rssi_max)s, %(sample_count)s,
                NOW(6), %(samples_raw)s
            )
            ON DUPLICATE KEY UPDATE
                rssi_mean = VALUES(rssi_mean),
                rssi_stdev = VALUES(rssi_stdev),
                rssi_min = VALUES(rssi_min),
                rssi_max = VALUES(rssi_max),
                sample_count = VALUES(sample_count),
                established_at = NOW(6),
                samples_raw = VALUES(samples_raw)
        """
        params = {
            "ap_mac": baseline["ap_mac"],
            "rssi_mean": baseline["rssi_mean"],
            "rssi_stdev": baseline["rssi_stdev"],
            "rssi_min": baseline["rssi_min"],
            "rssi_max": baseline["rssi_max"],
            "sample_count": baseline.get("sample_count", 0),
            "samples_raw": json.dumps(baseline.get("samples_raw", [])),
        }

        with self._get_connection() as (conn, cursor):
            cursor.execute(sql, params)
            baseline_id = cursor.lastrowid
            logger.info(
                "Baseline set for %s: mean=%.1f stdev=%.1f (%d samples)",
                params["ap_mac"], params["rssi_mean"],
                params["rssi_stdev"], params["sample_count"],
            )
            return baseline_id

    # ================================================================
    # Utility
    # ================================================================

    def execute_schema(self, schema_path: str) -> None:
        """Execute a SQL schema file to create tables."""
        try:
            with open(schema_path, "r") as f:
                sql_content = f.read()

            # Split on semicolons, execute each statement
            statements = [s.strip() for s in sql_content.split(";") if s.strip()]

            with self._get_connection() as (conn, cursor):
                for stmt in statements:
                    # Skip empty or comment-only statements
                    clean = stmt.strip()
                    if not clean or clean.startswith("--"):
                        continue
                    try:
                        cursor.execute(clean)
                    except MySQLError as e:
                        # Log but continue (e.g., IF NOT EXISTS handles dupes)
                        logger.warning("Schema statement warning: %s", e)

            logger.info("Schema executed from %s", schema_path)
        except FileNotFoundError:
            logger.error("Schema file not found: %s", schema_path)
            raise
        except Exception as e:
            logger.error("Schema execution failed: %s", e)
            raise

    def health_check(self) -> bool:
        """Verify the connection pool is working."""
        try:
            with self._get_connection() as (conn, cursor):
                cursor.execute("SELECT 1 AS ok")
                row = cursor.fetchone()
                return row is not None and row.get("ok") == 1
        except Exception:
            return False
