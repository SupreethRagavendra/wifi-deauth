"""
WIDS Config Manager — Read/Write System Configuration

Wraps the wids_config table (key-value store) with type-safe accessors.
Complex values (arrays, objects) are stored as JSON strings and
automatically deserialized on read.
"""

import json
import logging
from typing import Any, Dict, List, Optional

from .database import WIDSDatabase

logger = logging.getLogger("WIDS.Config")

# Default configuration values seeded on first run
DEFAULT_CONFIG = {
    "ap_mac":                  ("9E:A8:2C:C2:1F:D9",           "string"),
    "trusted_devices":         ('["4C:6F:9C:F4:FA:63"]',       "json"),
    "monitor_interface":       ("wlan1mon",                      "string"),
    "dwell_time":              ("250",                           "int"),
    "time_window":             ("5",                             "int"),
    "frame_threshold":         ("30",                            "int"),
    "level1_threshold":        ("40",                            "int"),
    "level2_threshold":        ("60",                            "int"),
    "level3_threshold":        ("85",                            "int"),
    "level4_threshold":        ("95",                            "int"),
    "level4_enabled":          ("true",                          "boolean"),
    "counter_attack_enabled":  ("false",                         "boolean"),
    "legal_mode":              ("conservative",                  "string"),
}


class ConfigManager:
    """
    Read/write interface to the wids_config table.

    Usage:
        cm = ConfigManager(db)
        cm.seed_defaults()            # one-time: populate missing keys
        threshold = cm.get_typed("frame_threshold")  # returns int(30)
        cm.set("frame_threshold", 50)
        all_cfg = cm.get_all()
    """

    def __init__(self, db: WIDSDatabase):
        self.db = db

    # ================================================================
    # Read
    # ================================================================

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Get a raw config value as a string."""
        sql = "SELECT config_value FROM wids_config WHERE config_key = %s"
        with self.db._get_connection() as (conn, cursor):
            cursor.execute(sql, (key,))
            row = cursor.fetchone()
            if row is None:
                return default
            return row["config_value"]

    def get_typed(self, key: str, default: Any = None) -> Any:
        """
        Get a config value auto-cast to its declared data_type.

        Returns:
            int, float, bool, parsed JSON, or raw string depending on
            the data_type column.
        """
        sql = """
            SELECT config_value, data_type
            FROM wids_config
            WHERE config_key = %s
        """
        with self.db._get_connection() as (conn, cursor):
            cursor.execute(sql, (key,))
            row = cursor.fetchone()
            if row is None:
                return default

            value = row["config_value"]
            dtype = row["data_type"]

            return self._cast(value, dtype, default)

    def get_all(self) -> Dict[str, Any]:
        """
        Get all config values as a dict, auto-cast by data_type.
        """
        sql = "SELECT config_key, config_value, data_type FROM wids_config"
        with self.db._get_connection() as (conn, cursor):
            cursor.execute(sql)
            rows = cursor.fetchall()

        result = {}
        for row in rows:
            result[row["config_key"]] = self._cast(
                row["config_value"], row["data_type"], None
            )
        return result

    # ================================================================
    # Write
    # ================================================================

    def set(self, key: str, value: Any, data_type: Optional[str] = None) -> None:
        """
        Set a config value. Auto-detects data_type if not specified.

        Args:
            key: config key name
            value: the value to store (will be serialized to string)
            data_type: optional override ('int', 'float', 'boolean', 'json', 'string')
        """
        # Auto-detect type
        if data_type is None:
            data_type = self._detect_type(value)

        # Serialize to string
        if isinstance(value, bool):
            str_value = "true" if value else "false"
        elif isinstance(value, (dict, list)):
            str_value = json.dumps(value)
        else:
            str_value = str(value)

        sql = """
            INSERT INTO wids_config (config_key, config_value, data_type)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE
                config_value = VALUES(config_value),
                data_type = VALUES(data_type)
        """
        with self.db._get_connection() as (conn, cursor):
            cursor.execute(sql, (key, str_value, data_type))
            logger.info("Config set: %s = %s (%s)", key, str_value, data_type)

    def set_many(self, settings: Dict[str, Any]) -> None:
        """Set multiple config values at once."""
        for key, value in settings.items():
            self.set(key, value)

    # ================================================================
    # Seed
    # ================================================================

    def seed_defaults(self) -> int:
        """
        Populate wids_config with default values for any missing keys.
        Existing keys are NOT overwritten.

        Returns:
            Number of keys seeded.
        """
        seeded = 0
        sql_check = "SELECT 1 FROM wids_config WHERE config_key = %s"
        sql_insert = """
            INSERT INTO wids_config (config_key, config_value, data_type)
            VALUES (%s, %s, %s)
        """

        with self.db._get_connection() as (conn, cursor):
            for key, (value, dtype) in DEFAULT_CONFIG.items():
                cursor.execute(sql_check, (key,))
                if cursor.fetchone() is None:
                    cursor.execute(sql_insert, (key, value, dtype))
                    seeded += 1
                    logger.debug("Seeded config: %s = %s", key, value)

        if seeded > 0:
            logger.info("Seeded %d default config keys", seeded)
        return seeded

    # ================================================================
    # Convenience getters for common settings
    # ================================================================

    @property
    def ap_mac(self) -> str:
        """Target AP MAC address."""
        return self.get("ap_mac", "")

    @property
    def monitor_interface(self) -> str:
        """Monitor mode interface name."""
        return self.get("monitor_interface", "wlan1mon")

    @property
    def trusted_devices(self) -> List[str]:
        """List of trusted device MAC addresses."""
        val = self.get_typed("trusted_devices", [])
        return val if isinstance(val, list) else []

    @property
    def time_window(self) -> int:
        """Frame counting window in seconds."""
        return self.get_typed("time_window", 5)

    @property
    def frame_threshold(self) -> int:
        """Minimum frames in window to consider an attack."""
        return self.get_typed("frame_threshold", 30)

    @property
    def level_thresholds(self) -> Dict[str, int]:
        """Prevention level confidence thresholds."""
        return {
            "level1": self.get_typed("level1_threshold", 40),
            "level2": self.get_typed("level2_threshold", 60),
            "level3": self.get_typed("level3_threshold", 85),
            "level4": self.get_typed("level4_threshold", 95),
        }

    @property
    def level4_enabled(self) -> bool:
        """Whether level 4 (counter-attack) is enabled."""
        return self.get_typed("level4_enabled", False)

    @property
    def counter_attack_enabled(self) -> bool:
        """Whether counter-attack mode is enabled."""
        return self.get_typed("counter_attack_enabled", False)

    @property
    def legal_mode(self) -> str:
        """Legal operation mode: conservative/moderate/aggressive."""
        return self.get("legal_mode", "conservative")

    # ================================================================
    # Internal helpers
    # ================================================================

    @staticmethod
    def _cast(value: Optional[str], dtype: str, default: Any) -> Any:
        """Cast a string value to its declared type."""
        if value is None:
            return default

        try:
            if dtype == "int":
                return int(value)
            elif dtype == "float":
                return float(value)
            elif dtype == "boolean":
                return value.lower() in ("true", "1", "yes")
            elif dtype == "json":
                return json.loads(value)
            else:
                return value
        except (ValueError, json.JSONDecodeError, TypeError) as e:
            logger.warning("Failed to cast '%s' as %s: %s", value, dtype, e)
            return default

    @staticmethod
    def _detect_type(value: Any) -> str:
        """Auto-detect the data_type for a Python value."""
        if isinstance(value, bool):
            return "boolean"
        elif isinstance(value, int):
            return "int"
        elif isinstance(value, float):
            return "float"
        elif isinstance(value, (dict, list)):
            return "json"
        else:
            return "string"
