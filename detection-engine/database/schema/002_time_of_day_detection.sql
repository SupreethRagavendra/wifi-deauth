-- ====================================================================
-- TIME-OF-DAY ANOMALY DETECTION TABLES
-- ====================================================================
-- Migration: 002_time_of_day_detection.sql
-- Purpose: Add tables for time-of-day based anomaly detection
-- Author: Algorithm Design Specialist
-- Date: 2026-02-07
-- ====================================================================

-- ====================================================================
-- 1. TIME_OF_DAY_BASELINES TABLE
-- ====================================================================
-- Purpose: Store per-BSSID, per-time-slot baseline statistics
-- Used for Z-score calculation in time anomaly detection
-- 
-- Statistical basis:
--   Z = |X - μ| / σ
--   Where μ and σ are maintained per (bssid, day_of_week, hour) slot
--   
-- Volume: 168 slots per BSSID (7 days × 24 hours)
-- ====================================================================

CREATE TABLE IF NOT EXISTS time_of_day_baselines (
    baseline_id         BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    
    -- Network identification
    bssid               CHAR(17)        NOT NULL 
                        COMMENT 'Network BSSID (Format: AA:BB:CC:DD:EE:FF)',
    institute_id        VARCHAR(36)     DEFAULT NULL
                        COMMENT 'Optional institute association',
    
    -- Time slot definition (168 unique combinations per BSSID)
    day_of_week         TINYINT UNSIGNED NOT NULL 
                        COMMENT '0=Monday, 1=Tuesday, ..., 6=Sunday',
    hour                TINYINT UNSIGNED NOT NULL 
                        COMMENT 'Hour in 24-hour format (0-23)',
    
    -- Baseline statistics (EMA-based)
    mean                DOUBLE          NOT NULL DEFAULT 0.0 
                        COMMENT 'Average frame rate (frames/minute)',
    variance            DOUBLE          NOT NULL DEFAULT 0.0 
                        COMMENT 'Variance of frame rate (σ²)',
    std_dev             DOUBLE          NOT NULL DEFAULT 2.0 
                        COMMENT 'Standard deviation (σ)',
    sample_count        INT UNSIGNED    NOT NULL DEFAULT 0 
                        COMMENT 'Number of observations (min 4 for validity)',
    
    -- Metadata
    last_updated        DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                        COMMENT 'Last baseline update time',
    created_at          DATETIME(6)     NOT NULL DEFAULT CURRENT_TIMESTAMP(6)
                        COMMENT 'Initial creation time',
    
    PRIMARY KEY (baseline_id),
    
    -- Unique constraint ensures one baseline per (bssid, day, hour) combination
    UNIQUE KEY uk_baseline_slot (bssid, day_of_week, hour),
    
    -- Indexes for efficient lookups
    INDEX idx_baseline_bssid (bssid),
    INDEX idx_baseline_institute (institute_id),
    INDEX idx_baseline_valid (bssid, sample_count),
    
    -- Constraints
    CONSTRAINT chk_day_of_week CHECK (day_of_week BETWEEN 0 AND 6),
    CONSTRAINT chk_hour CHECK (hour BETWEEN 0 AND 23),
    CONSTRAINT chk_mean CHECK (mean >= 0),
    CONSTRAINT chk_variance CHECK (variance >= 0),
    CONSTRAINT chk_std_dev CHECK (std_dev >= 0)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Time-of-day baseline statistics for Z-score anomaly detection';

-- ====================================================================
-- 2. HOLIDAY_CALENDAR TABLE
-- ====================================================================
-- Purpose: Store holidays for time anomaly score adjustment
-- During holidays, unusual activity is expected, so scores are reduced
-- ====================================================================

CREATE TABLE IF NOT EXISTS holiday_calendar (
    holiday_id          INT UNSIGNED    NOT NULL AUTO_INCREMENT,
    
    -- Holiday definition
    holiday_date        DATE            NOT NULL
                        COMMENT 'Date of the holiday',
    holiday_name        VARCHAR(100)    NOT NULL
                        COMMENT 'Human-readable name',
    
    -- Scope (NULL = global, applies to all institutes)
    institute_id        VARCHAR(36)     DEFAULT NULL
                        COMMENT 'NULL for global holidays, or specific institute ID',
    
    -- Score adjustment
    score_modifier      DECIMAL(3,2)    NOT NULL DEFAULT 0.70
                        COMMENT 'Multiplier for time anomaly score (0.70 = 30% reduction)',
    
    -- Recurrence handling
    is_annual           TINYINT(1)      NOT NULL DEFAULT 0
                        COMMENT 'If 1, holiday recurs annually (only month/day checked)',
    
    -- Metadata
    created_at          DATETIME        NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    PRIMARY KEY (holiday_id),
    INDEX idx_holiday_date (holiday_date),
    INDEX idx_holiday_institute (institute_id, holiday_date),
    INDEX idx_holiday_annual (is_annual, holiday_date),
    
    -- Constraints
    CONSTRAINT chk_score_modifier CHECK (score_modifier BETWEEN 0 AND 1.5)
    
) ENGINE=InnoDB
  DEFAULT CHARSET=utf8mb4
  COLLATE=utf8mb4_unicode_ci
  COMMENT='Holiday calendar for time anomaly detection adjustment';

-- ====================================================================
-- 3. SEED DATA: Common Holidays (India, adjustable per organization)
-- ====================================================================

INSERT INTO holiday_calendar (holiday_date, holiday_name, is_annual, score_modifier) VALUES
    -- Indian National Holidays
    ('2026-01-26', 'Republic Day', 1, 0.70),
    ('2026-08-15', 'Independence Day', 1, 0.70),
    ('2026-10-02', 'Gandhi Jayanti', 1, 0.70),
    
    -- Major Religious/Cultural Holidays (dates vary yearly, examples for 2026)
    ('2026-03-14', 'Holi', 0, 0.70),
    ('2026-04-10', 'Good Friday', 0, 0.70),
    ('2026-04-14', 'Ambedkar Jayanti', 1, 0.70),
    ('2026-10-20', 'Dussehra', 0, 0.70),
    ('2026-11-14', 'Diwali', 0, 0.60),  -- Lower modifier = more suspicious
    ('2026-12-25', 'Christmas', 1, 0.70),
    ('2026-01-01', 'New Year Day', 1, 0.70),
    
    -- Weekend-like holidays (offices typically closed)
    ('2026-05-01', 'Labour Day', 1, 0.75);

-- ====================================================================
-- 4. STORED PROCEDURE: Calculate Z-Score
-- ====================================================================
-- Provides a database-level Z-score calculation for analytics

DELIMITER //

CREATE PROCEDURE IF NOT EXISTS sp_calculate_zscore(
    IN p_bssid CHAR(17),
    IN p_day_of_week TINYINT,
    IN p_hour TINYINT,
    IN p_current_rate DOUBLE,
    OUT p_zscore DOUBLE,
    OUT p_score INT
)
BEGIN
    DECLARE v_mean DOUBLE DEFAULT 0;
    DECLARE v_std_dev DOUBLE DEFAULT 2.0;
    DECLARE v_sample_count INT DEFAULT 0;
    
    -- Fetch baseline
    SELECT mean, std_dev, sample_count
    INTO v_mean, v_std_dev, v_sample_count
    FROM time_of_day_baselines
    WHERE bssid = p_bssid
      AND day_of_week = p_day_of_week
      AND hour = p_hour;
    
    -- Handle cases
    IF v_sample_count < 4 THEN
        -- Cold start: use conservative approach
        SET p_zscore = 0;
        SET p_score = 0;
    ELSEIF v_std_dev < 0.001 THEN
        -- Zero variance
        IF ABS(p_current_rate - v_mean) < 0.001 THEN
            SET p_zscore = 0;
        ELSE
            SET p_zscore = 10.0;  -- Cap
        END IF;
    ELSE
        -- Normal calculation
        SET p_zscore = ABS(p_current_rate - v_mean) / v_std_dev;
    END IF;
    
    -- Convert Z-score to points
    IF p_zscore < 2.0 THEN
        SET p_score = 0;
    ELSEIF p_zscore < 3.0 THEN
        SET p_score = 8;
    ELSE
        SET p_score = 15;
    END IF;
END //

DELIMITER ;

-- ====================================================================
-- 5. VIEW: Baseline Coverage Report
-- ====================================================================
-- Shows how many time slots have valid baselines per network

CREATE OR REPLACE VIEW v_baseline_coverage AS
SELECT 
    bssid,
    institute_id,
    COUNT(*) AS total_slots,
    SUM(CASE WHEN sample_count >= 4 THEN 1 ELSE 0 END) AS valid_slots,
    ROUND(SUM(CASE WHEN sample_count >= 4 THEN 1 ELSE 0 END) / 168.0 * 100, 2) AS coverage_pct,
    MIN(sample_count) AS min_samples,
    MAX(sample_count) AS max_samples,
    AVG(sample_count) AS avg_samples,
    ROUND(AVG(mean), 4) AS avg_mean,
    ROUND(AVG(std_dev), 4) AS avg_std_dev,
    MAX(last_updated) AS last_updated
FROM time_of_day_baselines
GROUP BY bssid, institute_id;

-- ====================================================================
-- 6. VIEW: Upcoming Holidays
-- ====================================================================

CREATE OR REPLACE VIEW v_upcoming_holidays AS
SELECT 
    holiday_date,
    holiday_name,
    COALESCE(institute_id, 'GLOBAL') AS scope,
    score_modifier,
    is_annual,
    DATEDIFF(holiday_date, CURDATE()) AS days_until
FROM holiday_calendar
WHERE holiday_date >= CURDATE()
   OR is_annual = 1
ORDER BY 
    CASE 
        WHEN holiday_date >= CURDATE() THEN holiday_date
        ELSE DATE_ADD(holiday_date, INTERVAL 1 YEAR)
    END
LIMIT 20;

-- ====================================================================
-- 7. INDEX for Performance Optimization
-- ====================================================================

-- Covering index for the most common query pattern
CREATE INDEX IF NOT EXISTS idx_baseline_lookup_covering 
ON time_of_day_baselines (bssid, day_of_week, hour, mean, std_dev, sample_count);

-- ====================================================================
-- QUERY EXAMPLES (for reference)
-- ====================================================================
/*
-- 1. Check if a time slot has valid baseline
SELECT EXISTS(
    SELECT 1 FROM time_of_day_baselines
    WHERE bssid = 'AA:BB:CC:DD:EE:FF'
      AND day_of_week = 0  -- Monday
      AND hour = 14        -- 2 PM
      AND sample_count >= 4
);

-- 2. Get baseline statistics for a time slot
SELECT mean, std_dev, sample_count
FROM time_of_day_baselines
WHERE bssid = 'AA:BB:CC:DD:EE:FF'
  AND day_of_week = 2  -- Wednesday
  AND hour = 3;        -- 3 AM

-- 3. Check if today is a holiday
SELECT EXISTS(
    SELECT 1 FROM holiday_calendar
    WHERE holiday_date = CURDATE()
       OR (is_annual = 1 
           AND MONTH(holiday_date) = MONTH(CURDATE())
           AND DAY(holiday_date) = DAY(CURDATE()))
);

-- 4. Get global average for cold start
SELECT 
    AVG(mean) AS global_mean,
    AVG(std_dev) AS global_std_dev,
    SUM(sample_count) AS total_samples
FROM time_of_day_baselines
WHERE bssid = 'AA:BB:CC:DD:EE:FF'
  AND sample_count >= 4;

-- 5. View baseline coverage
SELECT * FROM v_baseline_coverage WHERE bssid = 'AA:BB:CC:DD:EE:FF';
*/
