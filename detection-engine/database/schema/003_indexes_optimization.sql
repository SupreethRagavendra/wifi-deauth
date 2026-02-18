-- ====================================================================
-- WiFi Deauth Attack Detection System - Indexes & Query Optimization
-- MySQL 8.0+ Required
-- ====================================================================
-- High-performance indexes for <3ms query response time
-- Optimized for real-time detection workload patterns
-- ====================================================================

-- ====================================================================
-- ADDITIONAL COVERING INDEXES FOR FRAME_TRACKING
-- ====================================================================
-- These indexes support specific query patterns with all needed columns

-- ================================================================
-- INDEX 1: Rate Analysis Query Support (Layer 1)
-- ================================================================
-- Covers: SELECT COUNT(*), MAX(captured_at), MIN(captured_at)
--         WHERE source_mac = ? AND bssid = ? AND captured_at BETWEEN ? AND ?
-- Performance: <1ms with partition pruning

-- Already created in core table, but adding covering index
CREATE INDEX idx_frame_rate_covering 
ON frame_tracking (source_mac, bssid, captured_at, frame_type, reason_code)
COMMENT 'Covering index for rate analysis - includes frame_type and reason_code';

-- ================================================================
-- INDEX 2: Broadcast Attack Detection
-- ================================================================
-- High priority: broadcast attacks (dest_mac = 'FF:FF:FF:FF:FF:FF')

CREATE INDEX idx_frame_broadcast 
ON frame_tracking (dest_mac, captured_at DESC, source_mac, bssid)
COMMENT 'Optimized for broadcast attack detection queries';

-- ================================================================
-- INDEX 3: Sequence Number Analysis (Layer 2)
-- ================================================================
-- Covers sequence gap detection queries

CREATE INDEX idx_frame_seq_analysis 
ON frame_tracking (source_mac, bssid, captured_at, sequence_number, frame_id)
COMMENT 'Covering index for sequence analysis with frame ordering';

-- ================================================================
-- INDEX 4: Reason Code Analysis
-- ================================================================
-- Some attacks use specific reason codes

CREATE INDEX idx_frame_reason_code 
ON frame_tracking (reason_code, frame_type, captured_at DESC)
COMMENT 'For reason code pattern analysis';

-- ================================================================
-- INDEX 5: RSSI Anomaly Detection
-- ================================================================
-- RSSI jumps can indicate spoofed frames

CREATE INDEX idx_frame_rssi 
ON frame_tracking (source_mac, captured_at, rssi)
COMMENT 'For RSSI-based anomaly detection';

-- ================================================================
-- INDEX 6: Combined MAC + Time for Dashboard
-- ================================================================

CREATE INDEX idx_frame_mac_combined 
ON frame_tracking (source_mac, dest_mac, captured_at DESC)
COMMENT 'Combined index for MAC-based dashboard queries';

-- ====================================================================
-- DETECTION_EVENTS ADDITIONAL INDEXES
-- ====================================================================

-- ================================================================
-- INDEX 7: Active Attack Monitoring
-- ================================================================

CREATE INDEX idx_event_active_attacks 
ON detection_events (attack_end, severity DESC, detected_at DESC)
COMMENT 'For finding ongoing attacks (attack_end IS NULL)';

-- ================================================================
-- INDEX 8: Attack Type Statistics
-- ================================================================

CREATE INDEX idx_event_type_stats 
ON detection_events (attack_type, detected_at DESC, confidence)
COMMENT 'For attack type distribution queries';

-- ================================================================
-- INDEX 9: Confidence-based Filtering
-- ================================================================

CREATE INDEX idx_event_confidence 
ON detection_events (confidence DESC, detected_at DESC)
COMMENT 'High-confidence detection retrieval';

-- ================================================================
-- INDEX 10: Response Tracking
-- ================================================================

CREATE INDEX idx_event_response 
ON detection_events (blocked, alert_sent, detected_at DESC)
COMMENT 'For tracking response actions';

-- ====================================================================
-- FUNCTION-BASED INDEXES (MySQL 8.0+ Virtual Columns)
-- ====================================================================

-- ================================================================
-- Add virtual column for date extraction (partition pruning helper)
-- ================================================================

ALTER TABLE frame_tracking 
ADD COLUMN captured_date DATE 
GENERATED ALWAYS AS (DATE(captured_at)) STORED
AFTER captured_at;

CREATE INDEX idx_frame_captured_date 
ON frame_tracking (captured_date, source_mac)
COMMENT 'Date-based queries with partition pruning';

-- ================================================================
-- Add virtual column for hour extraction (time anomaly detection)
-- ================================================================

ALTER TABLE frame_tracking 
ADD COLUMN captured_hour TINYINT UNSIGNED
GENERATED ALWAYS AS (HOUR(captured_at)) STORED
AFTER captured_date;

CREATE INDEX idx_frame_hour 
ON frame_tracking (captured_hour, bssid, source_mac)
COMMENT 'Hour-based time anomaly queries';

-- ====================================================================
-- BASELINE TABLES ADDITIONAL INDEXES
-- ====================================================================

-- ================================================================
-- Baseline freshness tracking
-- ================================================================

CREATE INDEX idx_baseline_mac_freshness 
ON baseline_mac_stats (mac_address, updated_at DESC)
COMMENT 'Find stale baselines for refresh';

CREATE INDEX idx_baseline_bssid_freshness 
ON baseline_bssid_stats (bssid, updated_at DESC)
COMMENT 'Find stale BSSID baselines';

-- ================================================================
-- Cold start identification
-- ================================================================

CREATE INDEX idx_baseline_mac_coldstart 
ON baseline_mac_stats (is_cold_start, mac_address)
COMMENT 'Find MACs needing baseline warmup';

-- ================================================================
-- Anomaly score tracking
-- ================================================================

CREATE INDEX idx_seq_pattern_score 
ON sequence_patterns (anomaly_score DESC, source_mac)
COMMENT 'Find high-anomaly MAC addresses';

-- ====================================================================
-- RATE_AGGREGATES OPTIMIZATION
-- ====================================================================

-- ================================================================
-- Dashboard time-range queries
-- ================================================================

CREATE INDEX idx_rate_agg_dashboard 
ON rate_aggregates (institute_id, granularity, bucket_start DESC, detection_count)
COMMENT 'Optimized dashboard aggregate queries';

-- ================================================================
-- Global statistics
-- ================================================================

CREATE INDEX idx_rate_agg_global 
ON rate_aggregates (scope_type, granularity, bucket_start DESC)
COMMENT 'Global statistics retrieval'
USING BTREE;

-- ====================================================================
-- INDEX STATISTICS AND ANALYSIS
-- ====================================================================

-- Update index statistics for optimal query planning
ANALYZE TABLE frame_tracking;
ANALYZE TABLE detection_events;
ANALYZE TABLE attack_sessions;
ANALYZE TABLE baseline_mac_stats;
ANALYZE TABLE baseline_bssid_stats;
ANALYZE TABLE rate_aggregates;
ANALYZE TABLE sequence_patterns;
ANALYZE TABLE time_baselines;
ANALYZE TABLE detection_thresholds;

-- ====================================================================
-- QUERY OPTIMIZER HINTS DOCUMENTATION
-- ====================================================================
/*
For optimal performance, use these optimizer hints in application queries:

1. Rate Analysis Query:
   SELECT /*+ INDEX(frame_tracking idx_frame_rate_analysis) */
          COUNT(*) as frame_count,
          MAX(captured_at) as last_frame
   FROM frame_tracking
   WHERE source_mac = ? AND bssid = ? 
     AND captured_at BETWEEN ? AND ?;

2. Sequence Analysis Query:
   SELECT /*+ INDEX(frame_tracking idx_frame_seq_analysis) */
          frame_id, sequence_number, captured_at
   FROM frame_tracking
   WHERE source_mac = ? AND bssid = ?
     AND captured_at >= ?
   ORDER BY captured_at ASC;

3. Broadcast Detection:
   SELECT /*+ INDEX(frame_tracking idx_frame_broadcast) */
          source_mac, COUNT(*) as broadcast_count
   FROM frame_tracking
   WHERE dest_mac = 'FF:FF:FF:FF:FF:FF'
     AND captured_at >= DATE_SUB(NOW(), INTERVAL 5 MINUTE)
   GROUP BY source_mac
   HAVING broadcast_count > 5;

4. Active Attack Dashboard:
   SELECT /*+ INDEX(detection_events idx_event_active_attacks) */
          *
   FROM detection_events
   WHERE attack_end IS NULL
     AND severity IN ('HIGH', 'CRITICAL')
   ORDER BY detected_at DESC
   LIMIT 50;
*/

-- ====================================================================
-- INDEX SIZE ESTIMATES
-- ====================================================================
/*
Table: frame_tracking (assuming 100M rows/day)
----------------------------------------------
Index Name                    | Estimated Size/Day
------------------------------|-------------------
PRIMARY (frame_id, captured_at) | ~1.5 GB
idx_frame_source_mac_time      | ~2.5 GB
idx_frame_dest_mac_time        | ~2.5 GB
idx_frame_bssid_time           | ~2.5 GB
idx_frame_rate_analysis        | ~3.0 GB
idx_frame_processing_queue     | ~1.0 GB
idx_frame_sequence             | ~3.5 GB
idx_frame_channel              | ~1.5 GB
idx_frame_institute            | ~2.0 GB
idx_frame_rate_covering        | ~4.0 GB
idx_frame_broadcast            | ~3.0 GB
idx_frame_seq_analysis         | ~4.0 GB
----------------------------------------------
Total Index Storage/Day        | ~31 GB
7-Day Total                    | ~217 GB

Recommendation: 
- Use NVMe SSD for index storage
- Consider index compression with KEY_BLOCK_SIZE
- Monitor index fragmentation weekly
*/
