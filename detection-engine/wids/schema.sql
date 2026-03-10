-- ====================================================================
-- WIDS — WiFi Intrusion Detection System
-- Complete Database Schema (MySQL 8.0+)
-- ====================================================================
-- Research-backed schema for deauthentication attack detection and
-- prevention using RSSI fingerprinting, beacon traps, traffic
-- correlation, and multi-method voting.
-- ====================================================================

-- ====================================================================
-- 1. wids_events — Attack Event Log
-- ====================================================================
-- Stores every detected deauth/disassoc attack event with full
-- forensic detail: RSSI deviation, attacker identification via voting,
-- sequence gaps, inter-arrival time analysis, and prevention level.
-- ====================================================================

CREATE TABLE IF NOT EXISTS wids_events (
    event_id            INT             NOT NULL AUTO_INCREMENT,
    
    -- When the event was detected (microsecond precision)
    timestamp           DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    
    -- Target access point MAC
    bssid               VARCHAR(17)     NOT NULL COMMENT 'Target AP BSSID',
    
    -- Claimed source MAC on the deauth frame (likely spoofed)
    source_mac          VARCHAR(17)     NOT NULL COMMENT 'Claimed attacker MAC (spoofed)',
    
    -- Victim client MAC
    victim_mac          VARCHAR(17)     DEFAULT NULL COMMENT 'Target client MAC',
    
    -- WiFi channel the attack was observed on
    channel             INT             DEFAULT NULL,
    
    -- 802.11 reason code from the deauth frame
    reason_code         INT             DEFAULT NULL COMMENT '802.11 reason code',
    
    -- Number of deauth frames observed in the 5-second window
    frame_count         INT             NOT NULL DEFAULT 0 COMMENT 'Frames in 5-sec window',
    
    -- Maximum RSSI observed for this event's frames
    max_rssi            FLOAT           DEFAULT NULL COMMENT 'Signal strength in dBm',
    
    -- RSSI fingerprinting result: does RSSI deviate from AP baseline?
    is_spoofed          BOOLEAN         NOT NULL DEFAULT FALSE COMMENT 'RSSI deviation detected',
    
    -- How far (dB) the deauth RSSI deviates from the AP baseline
    rssi_deviation      FLOAT           DEFAULT NULL COMMENT 'dB deviation from baseline',
    
    -- Real attacker MAC identified via multi-method voting
    real_attacker_mac   VARCHAR(17)     DEFAULT NULL COMMENT 'Identified via voting system',
    
    -- Confidence in the attacker identification (0-100%)
    attacker_confidence FLOAT           DEFAULT NULL COMMENT '0-100 percent',
    
    -- Which detection methods contributed to identification
    detection_methods   VARCHAR(255)    DEFAULT NULL COMMENT 'e.g. RSSI+BEACON_TRAP',
    
    -- Sequence number gap anomaly size
    sequence_gap        INT             DEFAULT NULL COMMENT 'Sequence number anomaly size',
    
    -- Inter-arrival time analysis score
    iat_analysis        FLOAT           DEFAULT NULL COMMENT 'Inter-arrival time score',
    
    -- Prevention level applied (0=none, 1-4 escalating)
    prevention_level    INT             NOT NULL DEFAULT 0 COMMENT '0=none, 1-4 escalating',
    
    -- Whether this event is still active (FALSE after 60 seconds)
    is_active           BOOLEAN         NOT NULL DEFAULT TRUE COMMENT 'FALSE after 60sec',
    
    PRIMARY KEY (event_id),
    
    -- ================================================================
    -- INDEXES
    -- ================================================================
    
    -- Time-series queries (recent events, dashboards)
    INDEX idx_wids_event_timestamp (timestamp DESC),
    
    -- Frequency counting: "how many deauths from this MAC in last N sec?"
    INDEX idx_wids_event_srcmac_time (source_mac, timestamp),
    
    -- Dashboard: show active events sorted by time
    INDEX idx_wids_event_active_time (is_active, timestamp DESC),
    
    -- Look up events by identified real attacker
    INDEX idx_wids_event_real_attacker (real_attacker_mac)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='WIDS attack event log with forensic detail';


-- ====================================================================
-- 2. wids_fingerprints — Attacker RF Signatures
-- ====================================================================
-- Per-MAC RF fingerprint: RSSI vector, phase offset, clock skew,
-- frame type histogram. Used for cross-MAC correlation when an
-- attacker changes MACs but keeps the same physical hardware.
-- ====================================================================

CREATE TABLE IF NOT EXISTS wids_fingerprints (
    fingerprint_id      INT             NOT NULL AUTO_INCREMENT,
    
    -- Currently observed MAC address
    mac_address         VARCHAR(17)     NOT NULL COMMENT 'Currently used MAC',
    
    -- Array of recent RSSI observations (JSON)
    rssi_vector         JSON            DEFAULT NULL COMMENT 'Array of RSSI samples',
    
    -- Statistical summary of RSSI
    rssi_mean           FLOAT           DEFAULT NULL,
    rssi_stdev          FLOAT           DEFAULT NULL,
    
    -- PHY-layer characteristic: carrier frequency offset
    phase_offset        FLOAT           DEFAULT NULL COMMENT 'PHY layer characteristic',
    
    -- Hardware timing drift (microseconds per beacon interval)
    clock_skew          FLOAT           DEFAULT NULL COMMENT 'Hardware timing drift',
    
    -- Observation window
    first_seen          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    last_seen           DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    
    -- Total packets observed from this MAC
    packet_count        INT             NOT NULL DEFAULT 0,
    
    -- Which 802.11 frame types this MAC has sent (JSON array)
    frame_types         JSON            DEFAULT NULL COMMENT 'Array of frame types seen',
    
    -- Trilateration coordinates if available
    spatial_coordinates JSON            DEFAULT NULL COMMENT '{"x": float, "y": float}',
    
    PRIMARY KEY (fingerprint_id),
    
    -- Fast lookup by MAC
    INDEX idx_wids_fp_mac (mac_address),
    
    -- Cleanup: find stale fingerprints
    INDEX idx_wids_fp_lastseen (last_seen)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Per-device RF fingerprints for cross-MAC correlation';


-- ====================================================================
-- 3. wids_blocked_devices — REMOVED (Design 5)
-- ====================================================================
-- MAC blocking has been deprecated in Design 5: The Deceptive Fortress.
-- Prevention tables are now managed by prevention_db.py (MySQL).
-- New tables: prevention_levels, physical_fingerprints, temporal_windows,
-- honeypot_activity, frame_filtering, evasion_events, forensic_reports.
-- ====================================================================



-- ====================================================================
-- 4. wids_audit_log — REMOVED (Design 5)
-- ====================================================================
-- Old prevention audit log replaced by Design 5 tables:
-- prevention_levels, frame_filtering, evasion_events, honeypot_activity.
-- ====================================================================



-- ====================================================================
-- 5. wids_config — System Configuration (Key-Value Store)
-- ====================================================================
-- All tunable parameters stored as key-value pairs. Complex values
-- (arrays, objects) stored as JSON strings in config_value.
-- ====================================================================

CREATE TABLE IF NOT EXISTS wids_config (
    config_key          VARCHAR(100)    NOT NULL,
    
    -- Value as text (JSON for complex types)
    config_value        TEXT            DEFAULT NULL,
    
    -- Data type hint for deserialization
    data_type           VARCHAR(20)     NOT NULL DEFAULT 'string'
                        COMMENT 'int, float, boolean, json, string',
    
    -- Last modification time
    last_updated        TIMESTAMP       NOT NULL DEFAULT CURRENT_TIMESTAMP
                        ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (config_key)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='WIDS system configuration key-value store';


-- ====================================================================
-- 6. ap_baseline — RSSI Ground Truth per AP
-- ====================================================================
-- Established from legitimate beacon frames. Used as the reference
-- for RSSI deviation detection: if a deauth frame's RSSI deviates
-- by more than max(3σ, 6dB) from this baseline, it is spoofed.
-- ====================================================================

CREATE TABLE IF NOT EXISTS ap_baseline (
    baseline_id         INT             NOT NULL AUTO_INCREMENT,
    
    -- AP MAC address (one baseline per AP)
    ap_mac              VARCHAR(17)     NOT NULL,
    
    -- Statistical summary
    rssi_mean           FLOAT           NOT NULL COMMENT 'Mean RSSI from beacons',
    rssi_stdev          FLOAT           NOT NULL COMMENT 'Standard deviation',
    rssi_min            FLOAT           NOT NULL,
    rssi_max            FLOAT           NOT NULL,
    
    -- How many beacon samples were used
    sample_count        INT             NOT NULL DEFAULT 0,
    
    -- When the baseline was established
    established_at      DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    
    -- Raw RSSI samples for recalculation
    samples_raw         JSON            DEFAULT NULL COMMENT 'Array of all RSSI values',
    
    PRIMARY KEY (baseline_id),
    
    -- One baseline per AP
    UNIQUE INDEX idx_ap_baseline_mac (ap_mac)

) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='AP RSSI baseline from beacon frames';


-- ====================================================================
-- SEED DATA: Default Configuration
-- ====================================================================

INSERT INTO wids_config (config_key, config_value, data_type) VALUES
    ('ap_mac',                   '9E:A8:2C:C2:1F:D9',                       'string'),
    ('trusted_devices',          '["4C:6F:9C:F4:FA:63"]',                   'json'),
    ('monitor_interface',        'wlan1mon',                                 'string'),
    ('dwell_time',               '250',                                      'int'),
    ('time_window',              '5',                                        'int'),
    ('frame_threshold',          '30',                                       'int'),
    ('level1_threshold',         '40',                                       'int'),
    ('level2_threshold',         '60',                                       'int'),
    ('level3_threshold',         '85',                                       'int'),
    ('level4_threshold',         '95',                                       'int'),
    ('level4_enabled',           'true',                                     'boolean'),
    ('counter_attack_enabled',   'false',                                    'boolean'),
    ('legal_mode',               'conservative',                             'string')
ON DUPLICATE KEY UPDATE
    config_value = VALUES(config_value),
    last_updated = CURRENT_TIMESTAMP;
