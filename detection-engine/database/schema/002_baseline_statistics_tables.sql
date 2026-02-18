-- ====================================================================
-- WiFi Deauth Attack Detection System - Baseline Statistics Tables
-- MySQL 8.0+ Required
-- ====================================================================
-- Purpose: Store baseline statistics for anomaly detection
-- These tables act as "materialized views" updated by scheduled jobs
-- ====================================================================

-- ====================================================================
-- 1. BASELINE_MAC_STATS TABLE
-- ====================================================================
-- Purpose: Store per-MAC address behavioral baselines
-- Updated: Every 5 minutes by aggregation job
-- Used by: Layer 1 (Rate Analysis), Layer 3 (Behavioral Analysis)
-- ====================================================================

CREATE TABLE IF NOT EXISTS baseline_mac_stats (
    stat_id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- MAC address being tracked
    mac_address         CHAR(17)        NOT NULL COMMENT 'Source MAC address',
    
    -- BSSID association (one MAC may have multiple BSSID entries)
    bssid               CHAR(17)        NOT NULL COMMENT 'Associated BSSID',
    
    -- Institute for multi-tenant isolation
    institute_id        VARCHAR(36)     DEFAULT NULL,
    
    -- Time window for this baseline
    window_start        DATETIME        NOT NULL,
    window_end          DATETIME        NOT NULL,
    window_type         ENUM('HOUR', 'DAY', 'WEEK') NOT NULL DEFAULT 'HOUR',
    
    -- ================================================================
    -- RATE STATISTICS (Layer 1)
    -- ================================================================
    
    -- Total frame counts
    total_frames        INT UNSIGNED    NOT NULL DEFAULT 0,
    deauth_frames       INT UNSIGNED    NOT NULL DEFAULT 0,
    disassoc_frames     INT UNSIGNED    NOT NULL DEFAULT 0,
    
    -- Rate statistics (frames per second)
    avg_rate            DECIMAL(10,4)   NOT NULL DEFAULT 0.0000,
    max_rate            DECIMAL(10,4)   NOT NULL DEFAULT 0.0000,
    stddev_rate         DECIMAL(10,4)   NOT NULL DEFAULT 0.0000,
    
    -- Percentiles for anomaly detection
    p50_rate            DECIMAL(10,4)   DEFAULT NULL COMMENT '50th percentile',
    p90_rate            DECIMAL(10,4)   DEFAULT NULL COMMENT '90th percentile',
    p95_rate            DECIMAL(10,4)   DEFAULT NULL COMMENT '95th percentile',
    p99_rate            DECIMAL(10,4)   DEFAULT NULL COMMENT '99th percentile',
    
    -- ================================================================
    -- SEQUENCE STATISTICS (Layer 2)
    -- ================================================================
    
    -- Sequence gap analysis
    avg_seq_gap         DECIMAL(8,4)    DEFAULT NULL COMMENT 'Average sequence gap',
    max_seq_gap         INT UNSIGNED    DEFAULT NULL COMMENT 'Maximum sequence gap observed',
    seq_anomaly_count   INT UNSIGNED    NOT NULL DEFAULT 0 COMMENT 'Count of sequence anomalies',
    
    -- ================================================================
    -- TEMPORAL STATISTICS (Layer 3)
    -- ================================================================
    
    -- Time distribution (JSON array of 24 hourly counts)
    hourly_distribution JSON            DEFAULT NULL COMMENT '24-element array of frame counts per hour',
    
    -- Day of week distribution (JSON array of 7 daily counts)
    daily_distribution  JSON            DEFAULT NULL COMMENT '7-element array for day-of-week distribution',
    
    -- Active time metrics
    first_seen_today    DATETIME        DEFAULT NULL,
    last_seen_today     DATETIME        DEFAULT NULL,
    active_hours        TINYINT UNSIGNED DEFAULT 0 COMMENT 'Hours with activity',
    
    -- ================================================================
    -- EXPONENTIAL MOVING AVERAGES (EMA)
    -- ================================================================
    -- For adaptive baseline calculation
    
    ema_rate            DECIMAL(10,4)   DEFAULT NULL COMMENT 'EMA of frame rate (alpha=0.1)',
    ema_seq_gap         DECIMAL(8,4)    DEFAULT NULL COMMENT 'EMA of sequence gaps',
    
    -- ================================================================
    -- METADATA
    -- ================================================================
    
    sample_count        INT UNSIGNED    NOT NULL DEFAULT 0 COMMENT 'Number of samples in baseline',
    confidence_level    DECIMAL(3,2)    NOT NULL DEFAULT 0.00 COMMENT 'Baseline confidence 0.00-1.00',
    
    -- Cold start indicator (less than 24 hours of data)
    is_cold_start       TINYINT(1)      NOT NULL DEFAULT 1,
    
    -- Timestamps
    created_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    
    PRIMARY KEY (stat_id),
    
    -- Unique constraint per MAC/BSSID/window combination
    UNIQUE KEY uk_mac_bssid_window (mac_address, bssid, window_start, window_type),
    
    -- Indexes for lookup
    INDEX idx_baseline_mac (mac_address, window_type, window_start DESC),
    INDEX idx_baseline_bssid (bssid, window_type, window_start DESC),
    INDEX idx_baseline_institute (institute_id, window_type, window_start DESC),
    INDEX idx_baseline_updated (updated_at DESC) COMMENT 'For incremental processing'
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Per-MAC behavioral baselines for anomaly detection';

-- ====================================================================
-- 2. BASELINE_BSSID_STATS TABLE
-- ====================================================================
-- Purpose: Store per-BSSID (Access Point) baselines
-- Used by: All layers for AP-level anomaly detection
-- ====================================================================

CREATE TABLE IF NOT EXISTS baseline_bssid_stats (
    stat_id             BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- BSSID being tracked
    bssid               CHAR(17)        NOT NULL COMMENT 'Access point BSSID',
    
    -- Institute for multi-tenant isolation
    institute_id        VARCHAR(36)     DEFAULT NULL,
    
    -- WiFi network reference
    wifi_id             VARCHAR(36)     DEFAULT NULL,
    
    -- Time window
    window_start        DATETIME        NOT NULL,
    window_end          DATETIME        NOT NULL,
    window_type         ENUM('HOUR', 'DAY', 'WEEK') NOT NULL DEFAULT 'HOUR',
    
    -- ================================================================
    -- CLIENT STATISTICS
    -- ================================================================
    
    -- Unique client count
    unique_clients      INT UNSIGNED    NOT NULL DEFAULT 0,
    new_clients         INT UNSIGNED    NOT NULL DEFAULT 0 COMMENT 'First-time clients this window',
    
    -- Client list (JSON array of MAC addresses)
    active_clients      JSON            DEFAULT NULL,
    
    -- ================================================================
    -- FRAME STATISTICS
    -- ================================================================
    
    total_frames        INT UNSIGNED    NOT NULL DEFAULT 0,
    deauth_frames       INT UNSIGNED    NOT NULL DEFAULT 0,
    disassoc_frames     INT UNSIGNED    NOT NULL DEFAULT 0,
    broadcast_frames    INT UNSIGNED    NOT NULL DEFAULT 0 COMMENT 'Frames to FF:FF:FF:FF:FF:FF',
    
    -- Rate statistics
    avg_rate            DECIMAL(10,4)   NOT NULL DEFAULT 0.0000,
    max_rate            DECIMAL(10,4)   NOT NULL DEFAULT 0.0000,
    stddev_rate         DECIMAL(10,4)   NOT NULL DEFAULT 0.0000,
    
    -- ================================================================
    -- ATTACK HISTORY
    -- ================================================================
    
    attack_count        INT UNSIGNED    NOT NULL DEFAULT 0 COMMENT 'Detected attacks this window',
    last_attack_at      DATETIME        DEFAULT NULL,
    
    -- ================================================================
    -- CHANNEL STATISTICS
    -- ================================================================
    
    primary_channel     TINYINT UNSIGNED DEFAULT NULL,
    channel_changes     INT UNSIGNED    NOT NULL DEFAULT 0,
    
    -- ================================================================
    -- SIGNAL STATISTICS
    -- ================================================================
    
    avg_rssi            TINYINT         DEFAULT NULL,
    min_rssi            TINYINT         DEFAULT NULL,
    max_rssi            TINYINT         DEFAULT NULL,
    
    -- ================================================================
    -- HEALTH SCORE
    -- ================================================================
    
    health_score        DECIMAL(5,2)    DEFAULT NULL COMMENT '0-100 AP health score',
    
    -- Metadata
    sample_count        INT UNSIGNED    NOT NULL DEFAULT 0,
    is_cold_start       TINYINT(1)      NOT NULL DEFAULT 1,
    
    -- Timestamps
    created_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    
    PRIMARY KEY (stat_id),
    
    UNIQUE KEY uk_bssid_window (bssid, window_start, window_type),
    INDEX idx_bssid_stats_lookup (bssid, window_type, window_start DESC),
    INDEX idx_bssid_stats_institute (institute_id, window_type, window_start DESC),
    INDEX idx_bssid_stats_wifi (wifi_id, window_type, window_start DESC)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Per-BSSID (AP) baselines for anomaly detection';

-- ====================================================================
-- 3. RATE_AGGREGATES TABLE (Time-Series)
-- ====================================================================
-- Purpose: Pre-aggregated rate statistics for fast dashboard queries
-- Granularity: 1-minute, 5-minute, 1-hour buckets
-- Retention: 1-min: 24h, 5-min: 7 days, 1-hour: 90 days
-- ====================================================================

CREATE TABLE IF NOT EXISTS rate_aggregates (
    agg_id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- Time bucket
    bucket_start        DATETIME        NOT NULL,
    bucket_end          DATETIME        NOT NULL,
    granularity         ENUM('1MIN', '5MIN', '1HOUR') NOT NULL,
    
    -- Aggregation scope
    scope_type          ENUM('GLOBAL', 'INSTITUTE', 'BSSID', 'MAC') NOT NULL,
    scope_id            VARCHAR(36)     DEFAULT NULL COMMENT 'ID based on scope_type',
    
    -- Institute for filtering
    institute_id        VARCHAR(36)     DEFAULT NULL,
    
    -- ================================================================
    -- FRAME COUNTS
    -- ================================================================
    
    total_frames        INT UNSIGNED    NOT NULL DEFAULT 0,
    deauth_frames       INT UNSIGNED    NOT NULL DEFAULT 0,
    disassoc_frames     INT UNSIGNED    NOT NULL DEFAULT 0,
    broadcast_frames    INT UNSIGNED    NOT NULL DEFAULT 0,
    
    -- ================================================================
    -- RATE METRICS
    -- ================================================================
    
    avg_rate            DECIMAL(10,4)   NOT NULL DEFAULT 0.0000,
    max_rate            DECIMAL(10,4)   NOT NULL DEFAULT 0.0000,
    min_rate            DECIMAL(10,4)   NOT NULL DEFAULT 0.0000,
    
    -- ================================================================
    -- DETECTION METRICS
    -- ================================================================
    
    detection_count     INT UNSIGNED    NOT NULL DEFAULT 0,
    false_positive_count INT UNSIGNED   NOT NULL DEFAULT 0,
    
    -- Severity distribution (JSON)
    severity_breakdown  JSON            DEFAULT NULL COMMENT '{"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}',
    
    -- ================================================================
    -- UNIQUE COUNTS
    -- ================================================================
    
    unique_sources      INT UNSIGNED    NOT NULL DEFAULT 0,
    unique_targets      INT UNSIGNED    NOT NULL DEFAULT 0,
    unique_bssids       INT UNSIGNED    NOT NULL DEFAULT 0,
    
    -- Timestamps
    created_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    
    PRIMARY KEY (agg_id),
    
    -- Unique constraint prevents duplicate buckets
    UNIQUE KEY uk_rate_agg (bucket_start, granularity, scope_type, scope_id),
    
    -- Time-based lookups
    INDEX idx_rate_agg_time (granularity, bucket_start DESC),
    INDEX idx_rate_agg_scope (scope_type, scope_id, granularity, bucket_start DESC),
    INDEX idx_rate_agg_institute (institute_id, granularity, bucket_start DESC)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Pre-aggregated rate statistics for dashboards';

-- ====================================================================
-- 4. SEQUENCE_PATTERNS TABLE
-- ====================================================================
-- Purpose: Store learned sequence number patterns per MAC/BSSID
-- Used by: Layer 2 (Sequence Validation)
-- ====================================================================

CREATE TABLE IF NOT EXISTS sequence_patterns (
    pattern_id          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- Source identification
    source_mac          CHAR(17)        NOT NULL,
    bssid               CHAR(17)        NOT NULL,
    
    -- Institute
    institute_id        VARCHAR(36)     DEFAULT NULL,
    
    -- ================================================================
    -- SEQUENCE PATTERN DATA
    -- ================================================================
    
    -- Last known sequence number
    last_sequence       SMALLINT UNSIGNED NOT NULL DEFAULT 0,
    last_seen_at        DATETIME(6)     NOT NULL,
    
    -- Sequence increment statistics
    -- Normal 802.11 increments by 1 for each frame
    avg_increment       DECIMAL(6,2)    NOT NULL DEFAULT 1.00,
    max_increment       SMALLINT UNSIGNED NOT NULL DEFAULT 1,
    
    -- Gap statistics (gaps > threshold indicate anomaly)
    gap_count           INT UNSIGNED    NOT NULL DEFAULT 0 COMMENT 'Total gaps detected',
    gap_threshold       SMALLINT UNSIGNED NOT NULL DEFAULT 10 COMMENT 'Max normal gap',
    
    -- Wraparound tracking (0-4095 cycle)
    wraparound_count    INT UNSIGNED    NOT NULL DEFAULT 0,
    last_wraparound     DATETIME        DEFAULT NULL,
    
    -- ================================================================
    -- PATTERN FINGERPRINT
    -- ================================================================
    
    -- Common increment patterns (JSON histogram)
    increment_histogram JSON            DEFAULT NULL COMMENT '{"1": 95.5, "2": 3.2, "4": 1.3}',
    
    -- Timing between frames (ms)
    avg_frame_interval  DECIMAL(10,2)   DEFAULT NULL COMMENT 'Average ms between frames',
    
    -- ================================================================
    -- ANOMALY TRACKING
    -- ================================================================
    
    anomaly_score       DECIMAL(5,2)    NOT NULL DEFAULT 0.00 COMMENT 'Current anomaly score 0-100',
    total_anomalies     INT UNSIGNED    NOT NULL DEFAULT 0,
    last_anomaly_at     DATETIME        DEFAULT NULL,
    
    -- Confidence in pattern (based on sample size)
    confidence          DECIMAL(3,2)    NOT NULL DEFAULT 0.00,
    sample_count        INT UNSIGNED    NOT NULL DEFAULT 0,
    
    -- Timestamps
    created_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    
    PRIMARY KEY (pattern_id),
    
    UNIQUE KEY uk_sequence_pattern (source_mac, bssid),
    INDEX idx_seq_pattern_mac (source_mac, last_seen_at DESC),
    INDEX idx_seq_pattern_bssid (bssid, last_seen_at DESC),
    INDEX idx_seq_pattern_anomaly (anomaly_score DESC, last_seen_at DESC)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Sequence number patterns for Layer 2 validation';

-- ====================================================================
-- 5. TIME_BASELINES TABLE
-- ====================================================================
-- Purpose: Store time-of-day baselines for Time Anomaly Detection
-- Used by: Layer 3 (Time Anomaly Detector)
-- ====================================================================

CREATE TABLE IF NOT EXISTS time_baselines (
    baseline_id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- Scope (can be global, institute, BSSID, or MAC-specific)
    scope_type          ENUM('GLOBAL', 'INSTITUTE', 'BSSID', 'MAC') NOT NULL,
    scope_id            VARCHAR(36)     DEFAULT NULL,
    
    -- Institute
    institute_id        VARCHAR(36)     DEFAULT NULL,
    
    -- ================================================================
    -- TIME SLOT DEFINITION
    -- ================================================================
    
    -- Time slot (0-23 for hour, 0-6 for day-of-week)
    slot_type           ENUM('HOUR_OF_DAY', 'DAY_OF_WEEK', 'HOUR_OF_WEEK') NOT NULL,
    slot_value          TINYINT UNSIGNED NOT NULL COMMENT '0-23 for hour, 0-6 for DOW, 0-167 for HOW',
    
    -- ================================================================
    -- BASELINE STATISTICS
    -- ================================================================
    
    -- Expected frame count in this slot
    expected_frames     DECIMAL(12,2)   NOT NULL DEFAULT 0.00,
    stddev_frames       DECIMAL(12,2)   NOT NULL DEFAULT 0.00,
    
    -- EMA for adaptive baseline (alpha = 0.1)
    ema_frames          DECIMAL(12,2)   NOT NULL DEFAULT 0.00,
    
    -- Min/Max observed
    min_frames          INT UNSIGNED    NOT NULL DEFAULT 0,
    max_frames          INT UNSIGNED    NOT NULL DEFAULT 0,
    
    -- Z-score threshold for this slot (may vary by time)
    z_threshold         DECIMAL(4,2)    NOT NULL DEFAULT 2.50,
    
    -- ================================================================
    -- CONTEXTUAL FLAGS
    -- ================================================================
    
    is_business_hours   TINYINT(1)      NOT NULL DEFAULT 0,
    is_high_activity    TINYINT(1)      NOT NULL DEFAULT 0,
    is_maintenance_window TINYINT(1)    NOT NULL DEFAULT 0,
    
    -- ================================================================
    -- METADATA
    -- ================================================================
    
    sample_count        INT UNSIGNED    NOT NULL DEFAULT 0,
    weeks_of_data       TINYINT UNSIGNED NOT NULL DEFAULT 0,
    confidence          DECIMAL(3,2)    NOT NULL DEFAULT 0.00,
    
    -- Timestamps
    created_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    
    PRIMARY KEY (baseline_id),
    
    UNIQUE KEY uk_time_baseline (scope_type, scope_id, slot_type, slot_value),
    INDEX idx_time_baseline_lookup (scope_type, scope_id, slot_type),
    INDEX idx_time_baseline_institute (institute_id, slot_type, slot_value)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Time-of-day baselines for Layer 3 time anomaly detection';

-- ====================================================================
-- 6. DETECTION_THRESHOLDS TABLE (Dynamic per-entity)
-- ====================================================================
-- Purpose: Store dynamically calculated thresholds per entity
-- Updated based on baseline statistics
-- ====================================================================

CREATE TABLE IF NOT EXISTS detection_thresholds (
    threshold_id        BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- Entity identification
    entity_type         ENUM('GLOBAL', 'INSTITUTE', 'BSSID', 'MAC') NOT NULL,
    entity_id           VARCHAR(36)     DEFAULT NULL COMMENT 'NULL for GLOBAL',
    
    -- Institute association
    institute_id        VARCHAR(36)     DEFAULT NULL,
    
    -- ================================================================
    -- LAYER 1 THRESHOLDS (Rate Analysis)
    -- ================================================================
    
    l1_deauth_rate_warn     DECIMAL(10,2) NOT NULL DEFAULT 5.00 COMMENT 'Warning threshold (frames/sec)',
    l1_deauth_rate_alert    DECIMAL(10,2) NOT NULL DEFAULT 10.00 COMMENT 'Alert threshold',
    l1_deauth_rate_critical DECIMAL(10,2) NOT NULL DEFAULT 20.00 COMMENT 'Critical threshold',
    
    l1_burst_count_warn     INT UNSIGNED NOT NULL DEFAULT 10,
    l1_burst_count_alert    INT UNSIGNED NOT NULL DEFAULT 25,
    l1_burst_count_critical INT UNSIGNED NOT NULL DEFAULT 50,
    
    l1_window_seconds       INT UNSIGNED NOT NULL DEFAULT 5 COMMENT 'Analysis window',
    
    -- ================================================================
    -- LAYER 2 THRESHOLDS (Sequence Validation)
    -- ================================================================
    
    l2_seq_gap_warn         SMALLINT UNSIGNED NOT NULL DEFAULT 10,
    l2_seq_gap_alert        SMALLINT UNSIGNED NOT NULL DEFAULT 50,
    l2_seq_gap_critical     SMALLINT UNSIGNED NOT NULL DEFAULT 200,
    
    l2_duplicate_ratio_warn DECIMAL(5,4) NOT NULL DEFAULT 0.0500,
    l2_duplicate_ratio_alert DECIMAL(5,4) NOT NULL DEFAULT 0.1000,
    
    -- ================================================================
    -- LAYER 3 THRESHOLDS (Context Analysis)
    -- ================================================================
    
    l3_time_zscore_warn     DECIMAL(4,2) NOT NULL DEFAULT 2.00,
    l3_time_zscore_alert    DECIMAL(4,2) NOT NULL DEFAULT 3.00,
    l3_time_zscore_critical DECIMAL(4,2) NOT NULL DEFAULT 4.00,
    
    l3_behavioral_deviation DECIMAL(5,4) NOT NULL DEFAULT 0.2000 COMMENT 'Max deviation from baseline',
    
    -- ================================================================
    -- COMBINED THRESHOLDS
    -- ================================================================
    
    total_score_warn        TINYINT UNSIGNED NOT NULL DEFAULT 40,
    total_score_alert       TINYINT UNSIGNED NOT NULL DEFAULT 60,
    total_score_critical    TINYINT UNSIGNED NOT NULL DEFAULT 80,
    
    -- ================================================================
    -- METADATA
    -- ================================================================
    
    -- Source of threshold values
    threshold_source    ENUM('DEFAULT', 'LEARNED', 'MANUAL') NOT NULL DEFAULT 'DEFAULT',
    
    -- When thresholds were last recalculated
    last_calculated     DATETIME        DEFAULT NULL,
    calculation_samples INT UNSIGNED    DEFAULT NULL,
    
    -- Override flag (prevents automatic updates)
    is_locked           TINYINT(1)      NOT NULL DEFAULT 0,
    
    -- Timestamps
    created_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    
    PRIMARY KEY (threshold_id),
    
    UNIQUE KEY uk_threshold_entity (entity_type, entity_id),
    INDEX idx_threshold_institute (institute_id),
    INDEX idx_threshold_type (entity_type)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Dynamic detection thresholds per entity';

-- ====================================================================
-- STORAGE ESTIMATES FOR BASELINE TABLES
-- ====================================================================
/*
TABLE                   | Row Size | Rows/Day      | Daily Storage | 7-Day Storage
------------------------|----------|---------------|---------------|---------------
baseline_mac_stats      | ~500 B   | ~100K         | ~50 MB        | ~350 MB
baseline_bssid_stats    | ~400 B   | ~10K          | ~4 MB         | ~28 MB
rate_aggregates         | ~300 B   | ~500K         | ~150 MB       | ~1 GB
sequence_patterns       | ~300 B   | ~50K (total)  | ~15 MB        | ~15 MB (static)
time_baselines          | ~200 B   | ~10K (total)  | ~2 MB         | ~2 MB (static)
detection_thresholds    | ~400 B   | ~1K (total)   | ~400 KB       | ~400 KB (static)
------------------------|----------|---------------|---------------|---------------
TOTAL (estimated)       |          |               | ~220 MB/day   | ~1.4 GB
*/
