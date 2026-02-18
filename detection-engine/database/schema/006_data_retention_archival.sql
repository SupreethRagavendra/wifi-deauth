-- ====================================================================
-- WiFi Deauth Attack Detection System - Data Retention & Archival
-- MySQL 8.0+ Required
-- ====================================================================
-- Retention policies, archival procedures, and cleanup jobs
-- ====================================================================

-- ====================================================================
-- RETENTION POLICY SUMMARY
-- ====================================================================
/*
TABLE                   | Hot Storage | Archive     | Final Deletion
------------------------|-------------|-------------|----------------
frame_tracking          | 7 days      | N/A (drop)  | 7 days
detection_events        | 30 days     | 1 year      | After archive
attack_sessions         | 90 days     | Indefinite  | Never
detection_evidence      | 30 days     | 1 year      | After archive
baseline_mac_stats      | 7 days      | N/A         | 7 days
baseline_bssid_stats    | 30 days     | N/A         | 30 days
rate_aggregates (1MIN)  | 24 hours    | N/A         | 24 hours
rate_aggregates (5MIN)  | 7 days      | N/A         | 7 days
rate_aggregates (1HOUR) | 90 days     | 1 year      | After archive
sequence_patterns       | Active only | N/A         | On inactivity
time_baselines          | Indefinite  | N/A         | N/A
*/

-- ====================================================================
-- 1. ARCHIVE TABLES
-- ====================================================================

-- ================================================================
-- Archive table for detection events
-- ================================================================
CREATE TABLE IF NOT EXISTS detection_events_archive (
    -- Same structure as detection_events
    event_id            BIGINT          NOT NULL,
    detected_at         DATETIME(6)     NOT NULL,
    attack_type         VARCHAR(50)     NOT NULL,
    confidence          DECIMAL(5,4)    NOT NULL,
    severity            VARCHAR(20)     NOT NULL,
    layer1_score        TINYINT UNSIGNED NOT NULL,
    layer2_score        TINYINT UNSIGNED NOT NULL,
    layer3_score        TINYINT UNSIGNED NOT NULL,
    total_score         TINYINT UNSIGNED NOT NULL,
    attacker_mac        CHAR(17)        NOT NULL,
    target_mac          CHAR(17)        DEFAULT NULL,
    target_bssid        CHAR(17)        NOT NULL,
    frame_count         INT UNSIGNED    NOT NULL,
    attack_duration_ms  INT UNSIGNED    NOT NULL,
    frames_per_second   DECIMAL(10,2)   DEFAULT NULL,
    attack_start        DATETIME(6)     NOT NULL,
    attack_end          DATETIME(6)     DEFAULT NULL,
    session_id          BIGINT UNSIGNED DEFAULT NULL,
    institute_id        VARCHAR(36)     DEFAULT NULL,
    wifi_id             VARCHAR(36)     DEFAULT NULL,
    blocked             TINYINT(1)      NOT NULL,
    acknowledged        TINYINT(1)      NOT NULL,
    evidence            JSON            DEFAULT NULL,
    created_at          DATETIME(6)     NOT NULL,
    
    -- Archive metadata
    archived_at         DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    archive_batch_id    VARCHAR(36)     NOT NULL,
    
    PRIMARY KEY (event_id),
    INDEX idx_archive_event_date (detected_at),
    INDEX idx_archive_event_batch (archive_batch_id),
    INDEX idx_archive_event_institute (institute_id, detected_at)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  ROW_FORMAT=COMPRESSED
  KEY_BLOCK_SIZE=8
  COMMENT='Archived detection events (30d - 1 year)';

-- ================================================================
-- Archive table for attack sessions
-- ================================================================
CREATE TABLE IF NOT EXISTS attack_sessions_archive (
    session_id          BIGINT UNSIGNED NOT NULL,
    started_at          DATETIME(6)     NOT NULL,
    ended_at            DATETIME(6)     DEFAULT NULL,
    status              VARCHAR(20)     NOT NULL,
    attack_type         VARCHAR(50)     NOT NULL,
    primary_attacker_mac CHAR(17)       NOT NULL,
    primary_target_bssid CHAR(17)       NOT NULL,
    total_events        INT UNSIGNED    NOT NULL,
    total_frames        INT UNSIGNED    NOT NULL,
    peak_rate           DECIMAL(10,2)   DEFAULT NULL,
    max_severity        VARCHAR(20)     DEFAULT NULL,
    affected_clients    JSON            DEFAULT NULL,
    auto_blocked        TINYINT(1)      NOT NULL,
    institute_id        VARCHAR(36)     DEFAULT NULL,
    analyst_notes       TEXT            DEFAULT NULL,
    created_at          DATETIME(6)     NOT NULL,
    
    -- Archive metadata
    archived_at         DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    archive_batch_id    VARCHAR(36)     NOT NULL,
    
    PRIMARY KEY (session_id),
    INDEX idx_archive_session_date (started_at),
    INDEX idx_archive_session_batch (archive_batch_id)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  ROW_FORMAT=COMPRESSED
  COMMENT='Archived attack sessions (90d - indefinite)';

-- ================================================================
-- Archive table for rate aggregates (hourly only)
-- ================================================================
CREATE TABLE IF NOT EXISTS rate_aggregates_archive (
    agg_id              BIGINT UNSIGNED NOT NULL,
    bucket_start        DATETIME        NOT NULL,
    bucket_end          DATETIME        NOT NULL,
    granularity         VARCHAR(10)     NOT NULL,
    scope_type          VARCHAR(20)     NOT NULL,
    scope_id            VARCHAR(36)     DEFAULT NULL,
    institute_id        VARCHAR(36)     DEFAULT NULL,
    total_frames        INT UNSIGNED    NOT NULL,
    deauth_frames       INT UNSIGNED    NOT NULL,
    disassoc_frames     INT UNSIGNED    NOT NULL,
    broadcast_frames    INT UNSIGNED    NOT NULL,
    avg_rate            DECIMAL(10,4)   NOT NULL,
    max_rate            DECIMAL(10,4)   NOT NULL,
    detection_count     INT UNSIGNED    NOT NULL,
    unique_sources      INT UNSIGNED    NOT NULL,
    unique_bssids       INT UNSIGNED    NOT NULL,
    created_at          DATETIME(6)     NOT NULL,
    
    -- Archive metadata
    archived_at         DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    archive_batch_id    VARCHAR(36)     NOT NULL,
    
    PRIMARY KEY (agg_id),
    INDEX idx_archive_rate_date (bucket_start),
    INDEX idx_archive_rate_batch (archive_batch_id)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  ROW_FORMAT=COMPRESSED
  COMMENT='Archived hourly rate aggregates (90d - 1 year)';

-- ====================================================================
-- 2. ARCHIVAL STORED PROCEDURES
-- ====================================================================

DELIMITER //

-- ================================================================
-- Procedure: Archive detection events older than 30 days
-- ================================================================
CREATE PROCEDURE IF NOT EXISTS sp_archive_detection_events(IN batch_size INT)
BEGIN
    DECLARE v_batch_id VARCHAR(36);
    DECLARE v_archived_count INT DEFAULT 0;
    DECLARE v_cutoff_date DATETIME;
    
    SET v_batch_id = UUID();
    SET v_cutoff_date = DATE_SUB(NOW(), INTERVAL 30 DAY);
    
    -- Start transaction
    START TRANSACTION;
    
    -- Insert into archive (batch processing)
    INSERT INTO detection_events_archive
    SELECT 
        event_id, detected_at, attack_type, confidence, severity,
        layer1_score, layer2_score, layer3_score, total_score,
        attacker_mac, target_mac, target_bssid,
        frame_count, attack_duration_ms, frames_per_second,
        attack_start, attack_end, session_id,
        institute_id, wifi_id, blocked, acknowledged,
        evidence, created_at,
        NOW() as archived_at,
        v_batch_id as archive_batch_id
    FROM detection_events
    WHERE detected_at < v_cutoff_date
      AND acknowledged = 1  -- Only archive acknowledged events
    LIMIT batch_size;
    
    SET v_archived_count = ROW_COUNT();
    
    -- Delete archived records from source
    DELETE FROM detection_events
    WHERE event_id IN (
        SELECT event_id 
        FROM detection_events_archive 
        WHERE archive_batch_id = v_batch_id
    );
    
    COMMIT;
    
    -- Log archival
    INSERT INTO archival_log (operation, table_name, records_processed, batch_id, completed_at)
    VALUES ('ARCHIVE', 'detection_events', v_archived_count, v_batch_id, NOW());
    
    SELECT v_archived_count as archived_count, v_batch_id as batch_id;
END //

-- ================================================================
-- Procedure: Archive attack sessions older than 90 days
-- ================================================================
CREATE PROCEDURE IF NOT EXISTS sp_archive_attack_sessions(IN batch_size INT)
BEGIN
    DECLARE v_batch_id VARCHAR(36);
    DECLARE v_archived_count INT DEFAULT 0;
    DECLARE v_cutoff_date DATETIME;
    
    SET v_batch_id = UUID();
    SET v_cutoff_date = DATE_SUB(NOW(), INTERVAL 90 DAY);
    
    START TRANSACTION;
    
    INSERT INTO attack_sessions_archive
    SELECT 
        session_id, started_at, ended_at, status, attack_type,
        primary_attacker_mac, primary_target_bssid,
        total_events, total_frames, peak_rate, max_severity,
        affected_clients, auto_blocked, institute_id,
        analyst_notes, created_at,
        NOW() as archived_at,
        v_batch_id as archive_batch_id
    FROM attack_sessions
    WHERE ended_at < v_cutoff_date
      AND status IN ('ENDED', 'MITIGATED', 'FALSE_POSITIVE')
    LIMIT batch_size;
    
    SET v_archived_count = ROW_COUNT();
    
    DELETE FROM attack_sessions
    WHERE session_id IN (
        SELECT session_id 
        FROM attack_sessions_archive 
        WHERE archive_batch_id = v_batch_id
    );
    
    COMMIT;
    
    INSERT INTO archival_log (operation, table_name, records_processed, batch_id, completed_at)
    VALUES ('ARCHIVE', 'attack_sessions', v_archived_count, v_batch_id, NOW());
    
    SELECT v_archived_count as archived_count, v_batch_id as batch_id;
END //

-- ================================================================
-- Procedure: Cleanup old rate aggregates
-- ================================================================
CREATE PROCEDURE IF NOT EXISTS sp_cleanup_rate_aggregates()
BEGIN
    DECLARE v_deleted_1min INT DEFAULT 0;
    DECLARE v_deleted_5min INT DEFAULT 0;
    DECLARE v_archived_1hour INT DEFAULT 0;
    
    -- Delete 1MIN aggregates older than 24 hours
    DELETE FROM rate_aggregates
    WHERE granularity = '1MIN'
      AND bucket_start < DATE_SUB(NOW(), INTERVAL 24 HOUR);
    SET v_deleted_1min = ROW_COUNT();
    
    -- Delete 5MIN aggregates older than 7 days
    DELETE FROM rate_aggregates
    WHERE granularity = '5MIN'
      AND bucket_start < DATE_SUB(NOW(), INTERVAL 7 DAY);
    SET v_deleted_5min = ROW_COUNT();
    
    -- Archive and delete 1HOUR aggregates older than 90 days
    INSERT INTO rate_aggregates_archive
    SELECT 
        agg_id, bucket_start, bucket_end, granularity, scope_type,
        scope_id, institute_id, total_frames, deauth_frames,
        disassoc_frames, broadcast_frames, avg_rate, max_rate,
        detection_count, unique_sources, unique_bssids, created_at,
        NOW() as archived_at,
        UUID() as archive_batch_id
    FROM rate_aggregates
    WHERE granularity = '1HOUR'
      AND bucket_start < DATE_SUB(NOW(), INTERVAL 90 DAY);
    SET v_archived_1hour = ROW_COUNT();
    
    DELETE FROM rate_aggregates
    WHERE granularity = '1HOUR'
      AND bucket_start < DATE_SUB(NOW(), INTERVAL 90 DAY);
    
    INSERT INTO archival_log (operation, table_name, records_processed, batch_id, completed_at)
    VALUES 
        ('DELETE', 'rate_aggregates_1min', v_deleted_1min, NULL, NOW()),
        ('DELETE', 'rate_aggregates_5min', v_deleted_5min, NULL, NOW()),
        ('ARCHIVE', 'rate_aggregates_1hour', v_archived_1hour, NULL, NOW());
    
    SELECT v_deleted_1min as deleted_1min, 
           v_deleted_5min as deleted_5min,
           v_archived_1hour as archived_1hour;
END //

-- ================================================================
-- Procedure: Cleanup old baselines
-- ================================================================
CREATE PROCEDURE IF NOT EXISTS sp_cleanup_baselines()
BEGIN
    DECLARE v_deleted_mac INT DEFAULT 0;
    DECLARE v_deleted_bssid INT DEFAULT 0;
    DECLARE v_deleted_patterns INT DEFAULT 0;
    
    -- Delete MAC baselines older than 7 days
    DELETE FROM baseline_mac_stats
    WHERE window_start < DATE_SUB(NOW(), INTERVAL 7 DAY);
    SET v_deleted_mac = ROW_COUNT();
    
    -- Delete BSSID baselines older than 30 days
    DELETE FROM baseline_bssid_stats
    WHERE window_start < DATE_SUB(NOW(), INTERVAL 30 DAY);
    SET v_deleted_bssid = ROW_COUNT();
    
    -- Delete sequence patterns not seen in 7 days
    DELETE FROM sequence_patterns
    WHERE last_seen_at < DATE_SUB(NOW(), INTERVAL 7 DAY);
    SET v_deleted_patterns = ROW_COUNT();
    
    INSERT INTO archival_log (operation, table_name, records_processed, batch_id, completed_at)
    VALUES 
        ('DELETE', 'baseline_mac_stats', v_deleted_mac, NULL, NOW()),
        ('DELETE', 'baseline_bssid_stats', v_deleted_bssid, NULL, NOW()),
        ('DELETE', 'sequence_patterns', v_deleted_patterns, NULL, NOW());
    
    SELECT v_deleted_mac as deleted_mac_baselines,
           v_deleted_bssid as deleted_bssid_baselines,
           v_deleted_patterns as deleted_patterns;
END //

-- ================================================================
-- Procedure: Cleanup detection evidence
-- ================================================================
CREATE PROCEDURE IF NOT EXISTS sp_cleanup_detection_evidence(IN batch_size INT)
BEGIN
    DECLARE v_deleted INT DEFAULT 0;
    
    -- Delete evidence for archived events (orphaned records)
    DELETE de FROM detection_evidence de
    LEFT JOIN detection_events ev ON de.event_id = ev.event_id
    WHERE ev.event_id IS NULL
    LIMIT batch_size;
    
    SET v_deleted = ROW_COUNT();
    
    INSERT INTO archival_log (operation, table_name, records_processed, batch_id, completed_at)
    VALUES ('DELETE', 'detection_evidence', v_deleted, NULL, NOW());
    
    SELECT v_deleted as deleted_evidence;
END //

-- ================================================================
-- Master cleanup procedure (runs all cleanups)
-- ================================================================
CREATE PROCEDURE IF NOT EXISTS sp_run_daily_maintenance()
BEGIN
    DECLARE v_start_time DATETIME;
    DECLARE v_end_time DATETIME;
    
    SET v_start_time = NOW();
    
    -- Log start
    INSERT INTO archival_log (operation, table_name, records_processed, batch_id, completed_at)
    VALUES ('MAINTENANCE_START', 'ALL', 0, NULL, NOW());
    
    -- 1. Drop old frame_tracking partitions (handled by event)
    CALL sp_drop_old_partitions(7);
    
    -- 2. Archive detection events
    CALL sp_archive_detection_events(10000);
    
    -- 3. Archive attack sessions
    CALL sp_archive_attack_sessions(1000);
    
    -- 4. Cleanup rate aggregates
    CALL sp_cleanup_rate_aggregates();
    
    -- 5. Cleanup baselines
    CALL sp_cleanup_baselines();
    
    -- 6. Cleanup orphaned evidence
    CALL sp_cleanup_detection_evidence(10000);
    
    -- 7. Optimize tables (weekly - check day)
    IF DAYOFWEEK(CURDATE()) = 1 THEN  -- Sunday
        OPTIMIZE TABLE detection_events;
        OPTIMIZE TABLE attack_sessions;
        OPTIMIZE TABLE baseline_mac_stats;
        OPTIMIZE TABLE baseline_bssid_stats;
        OPTIMIZE TABLE rate_aggregates;
    END IF;
    
    SET v_end_time = NOW();
    
    -- Log completion
    INSERT INTO archival_log (operation, table_name, records_processed, batch_id, completed_at)
    VALUES ('MAINTENANCE_COMPLETE', 'ALL', TIMESTAMPDIFF(SECOND, v_start_time, v_end_time), NULL, NOW());
    
    SELECT 'Maintenance completed' as status,
           v_start_time as started_at,
           v_end_time as completed_at,
           TIMESTAMPDIFF(SECOND, v_start_time, v_end_time) as duration_seconds;
END //

DELIMITER ;

-- ====================================================================
-- 3. ARCHIVAL LOG TABLE
-- ====================================================================

CREATE TABLE IF NOT EXISTS archival_log (
    log_id              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    operation           VARCHAR(50)     NOT NULL,
    table_name          VARCHAR(100)    NOT NULL,
    records_processed   INT             NOT NULL DEFAULT 0,
    batch_id            VARCHAR(36)     DEFAULT NULL,
    completed_at        DATETIME        NOT NULL,
    
    PRIMARY KEY (log_id),
    INDEX idx_archival_log_date (completed_at DESC),
    INDEX idx_archival_log_table (table_name, completed_at DESC)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COMMENT='Archival and cleanup operation log';

-- ====================================================================
-- 4. SCHEDULED EVENTS
-- ====================================================================

-- Enable event scheduler
SET GLOBAL event_scheduler = ON;

-- ================================================================
-- Event: Daily maintenance at 3 AM
-- ================================================================
CREATE EVENT IF NOT EXISTS evt_daily_maintenance
ON SCHEDULE EVERY 1 DAY
STARTS (TIMESTAMP(CURRENT_DATE) + INTERVAL 1 DAY + INTERVAL 3 HOUR)
COMMENT 'Daily archival and cleanup maintenance'
DO
BEGIN
    CALL sp_run_daily_maintenance();
END;

-- ================================================================
-- Event: Hourly rate aggregation
-- ================================================================
CREATE EVENT IF NOT EXISTS evt_hourly_aggregation
ON SCHEDULE EVERY 1 HOUR
STARTS (TIMESTAMP(CURRENT_DATE, '00:05:00'))
COMMENT 'Hourly rate aggregation job'
DO
BEGIN
    -- Call aggregation procedure (defined in separate file)
    -- CALL sp_aggregate_hourly_rates();
    SELECT 'Hourly aggregation would run here' as status;
END;

-- ================================================================
-- Event: 5-minute baseline update
-- ================================================================
CREATE EVENT IF NOT EXISTS evt_baseline_update
ON SCHEDULE EVERY 5 MINUTE
STARTS NOW()
COMMENT 'Update baseline statistics every 5 minutes'
DO
BEGIN
    -- Call baseline update procedure
    -- CALL sp_update_baselines();
    SELECT 'Baseline update would run here' as status;
END;

-- ====================================================================
-- 5. STORAGE MONITORING QUERIES
-- ====================================================================

-- ================================================================
-- Query: Table sizes with retention status
-- ================================================================
CREATE OR REPLACE VIEW v_storage_overview AS
SELECT 
    table_name,
    ROUND(data_length / 1024 / 1024 / 1024, 2) as data_gb,
    ROUND(index_length / 1024 / 1024 / 1024, 2) as index_gb,
    ROUND((data_length + index_length) / 1024 / 1024 / 1024, 2) as total_gb,
    table_rows as estimated_rows,
    CASE table_name
        WHEN 'frame_tracking' THEN '7 days (partition drop)'
        WHEN 'detection_events' THEN '30 days (archive)'
        WHEN 'attack_sessions' THEN '90 days (archive)'
        WHEN 'detection_evidence' THEN '30 days (cascade delete)'
        WHEN 'baseline_mac_stats' THEN '7 days (delete)'
        WHEN 'baseline_bssid_stats' THEN '30 days (delete)'
        WHEN 'rate_aggregates' THEN 'Varies by granularity'
        ELSE 'N/A'
    END as retention_policy
FROM information_schema.tables
WHERE table_schema = DATABASE()
  AND table_name IN (
      'frame_tracking', 'detection_events', 'attack_sessions',
      'detection_evidence', 'baseline_mac_stats', 'baseline_bssid_stats',
      'rate_aggregates', 'detection_events_archive', 'attack_sessions_archive'
  )
ORDER BY total_gb DESC;

-- ================================================================
-- Query: Partition sizes
-- ================================================================
CREATE OR REPLACE VIEW v_partition_sizes AS
SELECT 
    table_name,
    partition_name,
    partition_description as boundary,
    table_rows as estimated_rows,
    ROUND(data_length / 1024 / 1024, 2) as data_mb,
    ROUND(index_length / 1024 / 1024, 2) as index_mb
FROM information_schema.partitions
WHERE table_schema = DATABASE()
  AND table_name = 'frame_tracking'
  AND partition_name IS NOT NULL
ORDER BY partition_ordinal_position;

-- ================================================================
-- Query: Archival status
-- ================================================================
CREATE OR REPLACE VIEW v_archival_status AS
SELECT 
    table_name,
    DATE(completed_at) as date,
    SUM(CASE WHEN operation = 'ARCHIVE' THEN records_processed ELSE 0 END) as archived,
    SUM(CASE WHEN operation = 'DELETE' THEN records_processed ELSE 0 END) as deleted
FROM archival_log
WHERE completed_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
GROUP BY table_name, DATE(completed_at)
ORDER BY date DESC, table_name;
