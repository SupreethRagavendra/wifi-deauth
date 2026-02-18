-- ====================================================================
-- WiFi Deauth Attack Detection System - Core Detection Tables
-- MySQL 8.0+ Required
-- ====================================================================
-- Module 3: Detection Engine Database Schema
-- Performance Target: <20ms processing, <3ms query response
-- Expected Load: 1000-5000 frames/second
-- ====================================================================

-- ====================================================================
-- TABLE RELATIONSHIPS (ASCII DIAGRAM)
-- ====================================================================
/*
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                            WiFi Deauth Detection System Schema                           │
├─────────────────────────────────────────────────────────────────────────────────────────┤
│                                                                                          │
│  ┌──────────────────┐     ┌───────────────────┐     ┌─────────────────────┐             │
│  │   wifi_networks  │     │  detection_rules  │     │   attack_sessions   │             │
│  │  (existing)      │     │  (Configuration)  │     │  (Aggregated View)  │             │
│  └────────┬─────────┘     └─────────┬─────────┘     └──────────┬──────────┘             │
│           │                         │                          │                         │
│           │  1:N                    │ 1:N                      │ 1:N                     │
│           ▼                         ▼                          ▼                         │
│  ┌──────────────────────────────────────────────────────────────────────────────┐       │
│  │                           frame_tracking                                      │       │
│  │  (Partitioned by timestamp - HIGH VOLUME: 1000-5000/sec)                     │       │
│  │  ┌─────────────────────────────────────────────────────────────────────────┐ │       │
│  │  │ Partition: frame_tracking_p20260207 | frame_tracking_p20260208 | ...    │ │       │
│  │  └─────────────────────────────────────────────────────────────────────────┘ │       │
│  └──────────────────────────────────────────────────────────────────────────────┘       │
│           │                                                                              │
│           │  1:N                                                                         │
│           ▼                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────────────┐       │
│  │                           detection_events                                    │       │
│  │  (Detection results from 3-layer analysis)                                   │       │
│  └──────────────────────────────────────────────────────────────────────────────┘       │
│           │                                                                              │
│           │  M:N                                                                         │
│           ▼                                                                              │
│  ┌──────────────────────────────────────────────────────────────────────────────┐       │
│  │                           detection_evidence                                  │       │
│  │  (JSONB-style evidence storage for forensics)                                │       │
│  └──────────────────────────────────────────────────────────────────────────────┘       │
│                                                                                          │
│  ┌──────────────────┐     ┌───────────────────┐     ┌─────────────────────┐             │
│  │ baseline_stats   │     │ rate_aggregates   │     │ sequence_patterns   │             │
│  │ (Per-MAC/BSSID)  │     │ (Time-series)     │     │ (Behavioral)        │             │
│  └──────────────────┘     └───────────────────┘     └─────────────────────┘             │
│                                                                                          │
└─────────────────────────────────────────────────────────────────────────────────────────┘
*/

-- ====================================================================
-- 1. FRAME_TRACKING TABLE (High-Volume, Partitioned)
-- ====================================================================
-- Purpose: Store all deauth/disassoc frames for real-time analysis
-- Volume: 1000-5000 frames/second = 86M-432M frames/day
-- Storage: ~150 bytes/row = 13-65 GB/day (before compression)
-- Retention: 7 days with automatic partition drop
-- ====================================================================

CREATE TABLE IF NOT EXISTS frame_tracking (
    -- Primary identifier using BIGINT for high-volume auto-increment
    frame_id            BIGINT          NOT NULL AUTO_INCREMENT,
    
    -- Timestamp with microsecond precision for frame ordering
    -- Critical for sequence analysis and time-based queries
    captured_at         DATETIME(6)     NOT NULL,
    
    -- MAC addresses - fixed length for optimal storage
    -- Source MAC: Origin of the deauth frame
    source_mac          CHAR(17)        NOT NULL COMMENT 'Format: AA:BB:CC:DD:EE:FF',
    
    -- Destination MAC: Target of the deauth (may be broadcast FF:FF:FF:FF:FF:FF)
    dest_mac            CHAR(17)        NOT NULL COMMENT 'Format: AA:BB:CC:DD:EE:FF',
    
    -- BSSID: Access point identifier
    bssid               CHAR(17)        NOT NULL COMMENT 'Format: AA:BB:CC:DD:EE:FF',
    
    -- Frame type for filtering (DEAUTH, DISASSOC, etc.)
    frame_type          ENUM('DEAUTH', 'DISASSOC', 'AUTH_REJECT', 'ASSOC_REJECT') 
                        NOT NULL DEFAULT 'DEAUTH',
    
    -- Reason code from 802.11 standard (0-65535)
    reason_code         SMALLINT UNSIGNED NOT NULL DEFAULT 0 
                        COMMENT '802.11 Reason Code',
    
    -- Sequence number for gap detection (0-4095, 12-bit in 802.11)
    sequence_number     SMALLINT UNSIGNED NOT NULL 
                        COMMENT '802.11 Sequence Number (0-4095)',
    
    -- Signal strength for proximity analysis
    rssi                TINYINT         DEFAULT NULL COMMENT 'Signal strength in dBm (-100 to 0)',
    
    -- Channel information for multi-channel attack detection
    channel             TINYINT UNSIGNED DEFAULT NULL COMMENT 'WiFi channel (1-165)',
    
    -- Foreign key to wifi_networks (nullable for unknown networks)
    wifi_id             VARCHAR(36)     DEFAULT NULL,
    
    -- Institute association for multi-tenant support
    institute_id        VARCHAR(36)     DEFAULT NULL,
    
    -- Processing metadata
    processed           TINYINT(1)      NOT NULL DEFAULT 0 COMMENT 'Analyzed by detection engine',
    
    -- Detection layer results (stored as compact flags)
    layer1_score        TINYINT UNSIGNED DEFAULT NULL COMMENT 'Layer 1 score (0-100)',
    layer2_score        TINYINT UNSIGNED DEFAULT NULL COMMENT 'Layer 2 score (0-100)',
    layer3_score        TINYINT UNSIGNED DEFAULT NULL COMMENT 'Layer 3 score (0-100)',
    
    -- Record creation timestamp
    created_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    
    -- Primary key includes partition key for MySQL partitioning
    PRIMARY KEY (frame_id, captured_at),
    
    -- ================================================================
    -- INDEXES: Optimized for <3ms query performance
    -- ================================================================
    
    -- Index for MAC address + time range queries (most frequent)
    -- Covers: "Find all frames from MAC X in last N minutes"
    INDEX idx_frame_source_mac_time (source_mac, captured_at DESC),
    
    -- Index for destination MAC queries (broadcast attack detection)
    INDEX idx_frame_dest_mac_time (dest_mac, captured_at DESC),
    
    -- Index for BSSID-based queries (AP-specific analysis)
    INDEX idx_frame_bssid_time (bssid, captured_at DESC),
    
    -- Composite index for rate analysis (source + BSSID + time)
    INDEX idx_frame_rate_analysis (source_mac, bssid, captured_at DESC),
    
    -- Index for unprocessed frame queue
    INDEX idx_frame_processing_queue (processed, captured_at ASC),
    
    -- Index for sequence analysis
    INDEX idx_frame_sequence (source_mac, bssid, sequence_number, captured_at),
    
    -- Index for channel-based queries
    INDEX idx_frame_channel (channel, captured_at DESC),
    
    -- Institute-based filtering
    INDEX idx_frame_institute (institute_id, captured_at DESC)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  ROW_FORMAT=COMPRESSED
  KEY_BLOCK_SIZE=8
  COMMENT='High-volume frame tracking with 7-day retention'
  -- ================================================================
  -- PARTITIONING: By date for efficient data lifecycle management
  -- Each partition = 1 day of data (~86M-432M rows)
  -- ================================================================
  PARTITION BY RANGE (TO_DAYS(captured_at)) (
    PARTITION p_20260201 VALUES LESS THAN (TO_DAYS('2026-02-02')),
    PARTITION p_20260202 VALUES LESS THAN (TO_DAYS('2026-02-03')),
    PARTITION p_20260203 VALUES LESS THAN (TO_DAYS('2026-02-04')),
    PARTITION p_20260204 VALUES LESS THAN (TO_DAYS('2026-02-05')),
    PARTITION p_20260205 VALUES LESS THAN (TO_DAYS('2026-02-06')),
    PARTITION p_20260206 VALUES LESS THAN (TO_DAYS('2026-02-07')),
    PARTITION p_20260207 VALUES LESS THAN (TO_DAYS('2026-02-08')),
    PARTITION p_20260208 VALUES LESS THAN (TO_DAYS('2026-02-09')),
    PARTITION p_future VALUES LESS THAN MAXVALUE
);

-- ====================================================================
-- 2. DETECTION_EVENTS TABLE
-- ====================================================================
-- Purpose: Store detection results from 3-layer analysis
-- Volume: ~1-5% of frames (attacks detected) = ~1-20M events/day
-- Storage: ~500 bytes/row = 0.5-10 GB/day
-- ====================================================================

CREATE TABLE IF NOT EXISTS detection_events (
    -- Primary identifier
    event_id            BIGINT          NOT NULL AUTO_INCREMENT,
    
    -- Timestamp of detection
    detected_at         DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    
    -- Attack classification
    attack_type         ENUM('DEAUTH_FLOOD', 'TARGETED_DEAUTH', 'BROADCAST_DEAUTH',
                             'ROGUE_AP_DEAUTH', 'DISASSOC_FLOOD', 'KARMA_ATTACK',
                             'EVIL_TWIN', 'PMKID_ATTACK', 'UNKNOWN') 
                        NOT NULL DEFAULT 'UNKNOWN',
    
    -- Detection confidence (0.00 - 1.00)
    confidence          DECIMAL(5,4)    NOT NULL DEFAULT 0.0000 
                        COMMENT 'Detection confidence 0.0000-1.0000',
    
    -- Severity based on attack impact
    severity            ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') 
                        NOT NULL DEFAULT 'MEDIUM',
    
    -- Layer scores for explainability
    layer1_score        TINYINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Rate Analysis Score (0-40)',
    layer2_score        TINYINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Sequence Analysis Score (0-30)',
    layer3_score        TINYINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Context Analysis Score (0-30)',
    total_score         TINYINT UNSIGNED NOT NULL DEFAULT 0 COMMENT 'Combined Score (0-100)',
    
    -- Attack source identification
    attacker_mac        CHAR(17)        NOT NULL COMMENT 'Suspected attacker MAC',
    
    -- Target information
    target_mac          CHAR(17)        DEFAULT NULL COMMENT 'Target MAC or NULL for broadcast',
    target_bssid        CHAR(17)        NOT NULL COMMENT 'Targeted access point BSSID',
    
    -- Attack metrics
    frame_count         INT UNSIGNED    NOT NULL DEFAULT 0 COMMENT 'Frames in attack window',
    attack_duration_ms  INT UNSIGNED    NOT NULL DEFAULT 0 COMMENT 'Attack duration in milliseconds',
    frames_per_second   DECIMAL(10,2)   DEFAULT NULL COMMENT 'Attack rate',
    
    -- Time window of attack
    attack_start        DATETIME(6)     NOT NULL,
    attack_end          DATETIME(6)     DEFAULT NULL,
    
    -- Session tracking for correlated events
    session_id          BIGINT UNSIGNED DEFAULT NULL COMMENT 'FK to attack_sessions',
    
    -- Multi-tenant support
    institute_id        VARCHAR(36)     DEFAULT NULL,
    wifi_id             VARCHAR(36)     DEFAULT NULL,
    
    -- Response tracking
    alert_sent          TINYINT(1)      NOT NULL DEFAULT 0,
    blocked             TINYINT(1)      NOT NULL DEFAULT 0,
    acknowledged        TINYINT(1)      NOT NULL DEFAULT 0,
    acknowledged_by     VARCHAR(36)     DEFAULT NULL,
    acknowledged_at     DATETIME        DEFAULT NULL,
    
    -- JSON evidence for forensic analysis (MySQL 8.0+ JSON type)
    evidence            JSON            DEFAULT NULL 
                        COMMENT 'Detailed detection evidence and frame samples',
    
    -- Timestamps
    created_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    
    PRIMARY KEY (event_id),
    
    -- ================================================================
    -- INDEXES for real-time dashboard and alerting
    -- ================================================================
    
    -- Time-based queries (dashboard, recent attacks)
    INDEX idx_event_detected_at (detected_at DESC),
    
    -- Attacker tracking
    INDEX idx_event_attacker (attacker_mac, detected_at DESC),
    
    -- Target tracking
    INDEX idx_event_target (target_mac, detected_at DESC),
    INDEX idx_event_bssid (target_bssid, detected_at DESC),
    
    -- Severity-based alerting
    INDEX idx_event_severity_time (severity, detected_at DESC),
    
    -- Unacknowledged alerts
    INDEX idx_event_unack (acknowledged, severity DESC, detected_at DESC),
    
    -- Session correlation
    INDEX idx_event_session (session_id, detected_at),
    
    -- Multi-tenant filtering
    INDEX idx_event_institute (institute_id, detected_at DESC),
    
    -- Composite for dashboard queries
    INDEX idx_event_dashboard (institute_id, severity, detected_at DESC),
    
    -- Full-text on evidence JSON (MySQL 8.0.17+)
    -- Note: For JSON search, use JSON_CONTAINS or generated columns
    
    CONSTRAINT fk_event_session 
        FOREIGN KEY (session_id) REFERENCES attack_sessions(session_id)
        ON DELETE SET NULL
        
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Detection events from 3-layer analysis';

-- ====================================================================
-- 3. ATTACK_SESSIONS TABLE
-- ====================================================================
-- Purpose: Aggregate related detection events into attack sessions
-- Volume: ~1% of events = ~10K-200K sessions/day
-- Storage: ~1KB/row = 10-200 MB/day
-- ====================================================================

CREATE TABLE IF NOT EXISTS attack_sessions (
    session_id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- Session timeline
    started_at          DATETIME(6)     NOT NULL,
    ended_at            DATETIME(6)     DEFAULT NULL,
    last_activity       DATETIME(6)     NOT NULL,
    
    -- Session status
    status              ENUM('ACTIVE', 'ENDED', 'MITIGATED', 'FALSE_POSITIVE') 
                        NOT NULL DEFAULT 'ACTIVE',
    
    -- Attack classification (may evolve during session)
    attack_type         ENUM('DEAUTH_FLOOD', 'TARGETED_DEAUTH', 'BROADCAST_DEAUTH',
                             'ROGUE_AP_DEAUTH', 'DISASSOC_FLOOD', 'KARMA_ATTACK',
                             'EVIL_TWIN', 'PMKID_ATTACK', 'UNKNOWN') 
                        NOT NULL DEFAULT 'UNKNOWN',
    
    -- Primary attacker (session may involve multiple)
    primary_attacker_mac CHAR(17)       NOT NULL,
    
    -- Primary target
    primary_target_bssid CHAR(17)       NOT NULL,
    
    -- Aggregated metrics
    total_events        INT UNSIGNED    NOT NULL DEFAULT 0,
    total_frames        INT UNSIGNED    NOT NULL DEFAULT 0,
    peak_rate           DECIMAL(10,2)   DEFAULT NULL COMMENT 'Peak frames/second',
    avg_confidence      DECIMAL(5,4)    DEFAULT NULL,
    max_severity        ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') DEFAULT 'LOW',
    
    -- Associated targets (JSON array of MACs)
    affected_clients    JSON            DEFAULT NULL,
    
    -- Response actions taken
    auto_blocked        TINYINT(1)      NOT NULL DEFAULT 0,
    blocked_at          DATETIME        DEFAULT NULL,
    block_duration_min  INT UNSIGNED    DEFAULT NULL,
    
    -- Multi-tenant
    institute_id        VARCHAR(36)     DEFAULT NULL,
    
    -- Notes and investigation
    analyst_notes       TEXT            DEFAULT NULL,
    
    -- Timestamps
    created_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    
    PRIMARY KEY (session_id),
    
    -- Indexes
    INDEX idx_session_status (status, last_activity DESC),
    INDEX idx_session_attacker (primary_attacker_mac, started_at DESC),
    INDEX idx_session_target (primary_target_bssid, started_at DESC),
    INDEX idx_session_institute (institute_id, status, started_at DESC),
    INDEX idx_session_active (status, last_activity DESC) COMMENT 'Active session lookup'
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Aggregated attack sessions';

-- ====================================================================
-- 4. DETECTION_RULES TABLE (Enhanced from existing seed data)
-- ====================================================================
-- Purpose: Configurable detection rules per layer
-- ====================================================================

CREATE TABLE IF NOT EXISTS detection_rules (
    rule_id             INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    
    -- Rule identification
    rule_name           VARCHAR(100)    NOT NULL,
    rule_description    TEXT            NOT NULL,
    
    -- Layer assignment
    detection_layer     ENUM('LAYER_1', 'LAYER_2', 'LAYER_3', 'ALL') NOT NULL,
    
    -- Rule thresholds and parameters (JSON)
    thresholds          JSON            NOT NULL COMMENT 'Layer-specific threshold configuration',
    
    -- Rule priority (higher = more weight)
    priority            TINYINT UNSIGNED NOT NULL DEFAULT 50 COMMENT '0-100, higher = more important',
    
    -- Default severity when rule triggers
    severity            ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL DEFAULT 'MEDIUM',
    
    -- Rule status
    enabled             TINYINT(1)      NOT NULL DEFAULT 1,
    
    -- Per-institute overrides allowed
    allow_override      TINYINT(1)      NOT NULL DEFAULT 1,
    
    -- Timestamps
    created_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    PRIMARY KEY (rule_id),
    UNIQUE KEY uk_rule_name (rule_name),
    INDEX idx_rule_layer (detection_layer, enabled)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Detection rule configurations';

-- ====================================================================
-- 5. DETECTION_EVIDENCE TABLE
-- ====================================================================
-- Purpose: Detailed evidence storage for forensic analysis
-- Stores frame samples and analysis artifacts
-- ====================================================================

CREATE TABLE IF NOT EXISTS detection_evidence (
    evidence_id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- Link to detection event
    event_id            BIGINT          NOT NULL,
    
    -- Evidence type
    evidence_type       ENUM('FRAME_SAMPLE', 'RATE_ANALYSIS', 'SEQUENCE_GAP',
                             'TIME_ANOMALY', 'BEHAVIORAL', 'RSSI_JUMP', 'CORRELATION')
                        NOT NULL,
    
    -- Evidence data (JSON for flexibility)
    evidence_data       JSON            NOT NULL,
    
    -- Human-readable summary
    summary             VARCHAR(500)    DEFAULT NULL,
    
    -- Timestamps
    created_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    
    PRIMARY KEY (evidence_id),
    INDEX idx_evidence_event (event_id),
    INDEX idx_evidence_type (evidence_type, created_at DESC),
    
    CONSTRAINT fk_evidence_event 
        FOREIGN KEY (event_id) REFERENCES detection_events(event_id)
        ON DELETE CASCADE
        
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Detailed forensic evidence';

-- ====================================================================
-- STORAGE ESTIMATES
-- ====================================================================
/*
TABLE                   | Row Size | Daily Volume    | Daily Storage | 7-Day Storage
------------------------|----------|-----------------|---------------|---------------
frame_tracking          | ~150 B   | 86M-432M rows   | 13-65 GB      | 91-455 GB
detection_events        | ~500 B   | 0.9M-4.3M rows  | 0.5-2.2 GB    | 3.5-15 GB
attack_sessions         | ~1 KB    | 10K-200K rows   | 10-200 MB     | 70-1.4 GB
detection_evidence      | ~2 KB    | 0.9M-4.3M rows  | 1.8-8.6 GB    | 13-60 GB
detection_rules         | ~500 B   | <100 rows       | <50 KB        | <50 KB
------------------------|----------|-----------------|---------------|---------------
TOTAL (estimated)       |          |                 | 15-76 GB/day  | 108-532 GB

With ROW_FORMAT=COMPRESSED (Key Block Size 8):
- Expect 40-60% compression ratio
- Actual storage: 6-45 GB/day, 65-320 GB/7-days
*/

DELIMITER //

-- ====================================================================
-- STORED PROCEDURE: Add future partitions
-- ====================================================================
CREATE PROCEDURE IF NOT EXISTS sp_add_frame_partition(IN partition_date DATE)
BEGIN
    DECLARE partition_name VARCHAR(20);
    DECLARE next_date DATE;
    
    SET partition_name = CONCAT('p_', DATE_FORMAT(partition_date, '%Y%m%d'));
    SET next_date = DATE_ADD(partition_date, INTERVAL 1 DAY);
    
    SET @sql = CONCAT(
        'ALTER TABLE frame_tracking REORGANIZE PARTITION p_future INTO (',
        'PARTITION ', partition_name, ' VALUES LESS THAN (TO_DAYS(''', next_date, ''')),',
        'PARTITION p_future VALUES LESS THAN MAXVALUE)'
    );
    
    PREPARE stmt FROM @sql;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
    
    SELECT CONCAT('Added partition: ', partition_name) AS result;
END //

-- ====================================================================
-- STORED PROCEDURE: Drop old partitions (retention policy)
-- ====================================================================
CREATE PROCEDURE IF NOT EXISTS sp_drop_old_partitions(IN retention_days INT)
BEGIN
    DECLARE done INT DEFAULT FALSE;
    DECLARE part_name VARCHAR(64);
    DECLARE part_desc VARCHAR(64);
    DECLARE cutoff_days INT;
    
    DECLARE cur CURSOR FOR 
        SELECT PARTITION_NAME, PARTITION_DESCRIPTION 
        FROM INFORMATION_SCHEMA.PARTITIONS 
        WHERE TABLE_SCHEMA = DATABASE() 
          AND TABLE_NAME = 'frame_tracking'
          AND PARTITION_NAME != 'p_future'
          AND PARTITION_DESCRIPTION != 'MAXVALUE';
    
    DECLARE CONTINUE HANDLER FOR NOT FOUND SET done = TRUE;
    
    SET cutoff_days = TO_DAYS(DATE_SUB(CURDATE(), INTERVAL retention_days DAY));
    
    OPEN cur;
    
    read_loop: LOOP
        FETCH cur INTO part_name, part_desc;
        IF done THEN
            LEAVE read_loop;
        END IF;
        
        IF CAST(part_desc AS UNSIGNED) < cutoff_days THEN
            SET @sql = CONCAT('ALTER TABLE frame_tracking DROP PARTITION ', part_name);
            PREPARE stmt FROM @sql;
            EXECUTE stmt;
            DEALLOCATE PREPARE stmt;
            SELECT CONCAT('Dropped partition: ', part_name) AS result;
        END IF;
    END LOOP;
    
    CLOSE cur;
END //

DELIMITER ;

-- ====================================================================
-- EVENT: Daily partition maintenance
-- ====================================================================

-- Enable event scheduler (run once on server)
-- SET GLOBAL event_scheduler = ON;

CREATE EVENT IF NOT EXISTS evt_daily_partition_maintenance
ON SCHEDULE EVERY 1 DAY
STARTS (TIMESTAMP(CURRENT_DATE) + INTERVAL 1 DAY + INTERVAL 2 HOUR)
COMMENT 'Daily partition management: add new, drop old'
DO
BEGIN
    -- Add partition for 7 days ahead
    CALL sp_add_frame_partition(DATE_ADD(CURDATE(), INTERVAL 7 DAY));
    
    -- Drop partitions older than 7 days
    CALL sp_drop_old_partitions(7);
END;
