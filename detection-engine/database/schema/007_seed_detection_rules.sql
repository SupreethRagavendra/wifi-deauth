-- ====================================================================
-- WiFi Deauth Attack Detection System - Default Detection Rules
-- MySQL 8.0+ Required
-- ====================================================================
-- Seed data for detection rules configuration
-- Rules for 3-layer detection with 97% target accuracy
-- ====================================================================

-- ====================================================================
-- CLEAR EXISTING RULES (if re-seeding)
-- ====================================================================
-- TRUNCATE TABLE detection_rules;

-- ====================================================================
-- LAYER 1: RATE-BASED DETECTION RULES
-- ====================================================================
-- Purpose: Detect frame rate anomalies (deauth floods, bursts)
-- Contribution: Up to 40 points in total score
-- ====================================================================

INSERT INTO detection_rules (rule_name, rule_description, detection_layer, thresholds, priority, severity, enabled)
VALUES
-- ================================================================
-- Rule 1: Deauth Flood Detection
-- ================================================================
(
    'deauth_flood_basic',
    'Detect basic deauthentication flood attacks based on frame rate. Triggers when deauth frames exceed threshold per second from a single source.',
    'LAYER_1',
    JSON_OBJECT(
        'deauth_rate_per_sec', 10,
        'window_seconds', 5,
        'min_frames_trigger', 15,
        'score_weight', 15,
        'score_formula', 'min(15, floor(rate / 10) * 3)'
    ),
    90,
    'HIGH',
    1
),
-- ================================================================
-- Rule 2: Broadcast Deauth Detection (Higher severity)
-- ================================================================
(
    'broadcast_deauth_flood',
    'Detect broadcast deauth attacks targeting FF:FF:FF:FF:FF:FF. Any broadcast deauth is inherently suspicious as legitimate APs rarely send broadcast deauth.',
    'LAYER_1',
    JSON_OBJECT(
        'broadcast_rate_per_sec', 3,
        'window_seconds', 5,
        'min_frames_trigger', 5,
        'score_weight', 20,
        'score_formula', 'min(20, broadcast_count * 4)'
    ),
    95,
    'CRITICAL',
    1
),
-- ================================================================
-- Rule 3: Disassociation Flood
-- ================================================================
(
    'disassoc_flood_basic',
    'Detect disassociation flood attacks. Similar to deauth but uses disassociation frames.',
    'LAYER_1',
    JSON_OBJECT(
        'disassoc_rate_per_sec', 10,
        'window_seconds', 5,
        'min_frames_trigger', 15,
        'score_weight', 12,
        'score_formula', 'min(12, floor(rate / 10) * 2.5)'
    ),
    85,
    'HIGH',
    1
),
-- ================================================================
-- Rule 4: Single Target Attack
-- ================================================================
(
    'single_target_attack',
    'Detect targeted attacks focusing on a single client MAC address. Indicates deliberate targeting rather than broad attack.',
    'LAYER_1',
    JSON_OBJECT(
        'frames_to_single_target', 10,
        'window_seconds', 10,
        'unique_target_threshold', 1,
        'score_weight', 10,
        'score_formula', 'min(10, floor(target_frames / 5) * 2)'
    ),
    80,
    'HIGH',
    1
),
-- ================================================================
-- Rule 5: Multi-AP Attack
-- ================================================================
(
    'multi_ap_attack',
    'Detect attacks targeting multiple access points from single source. Indicates coordinated attack or reconnaissance.',
    'LAYER_1',
    JSON_OBJECT(
        'min_aps_targeted', 3,
        'window_seconds', 30,
        'min_frames_per_ap', 5,
        'score_weight', 15,
        'score_formula', 'min(15, ap_count * 3)'
    ),
    75,
    'CRITICAL',
    1
),
-- ================================================================
-- Rule 6: Burst Detection (Sub-second)
-- ================================================================
(
    'rapid_burst_attack',
    'Detect rapid frame bursts within sub-second windows. Characteristic of automated attack tools.',
    'LAYER_1',
    JSON_OBJECT(
        'burst_threshold', 20,
        'burst_window_ms', 500,
        'score_weight', 12,
        'score_formula', 'min(12, floor(burst_count / 10) * 4)'
    ),
    88,
    'HIGH',
    1
);

-- ====================================================================
-- LAYER 2: SEQUENCE-BASED DETECTION RULES
-- ====================================================================
-- Purpose: Detect sequence number anomalies (spoofed frames)
-- Contribution: Up to 30 points in total score
-- ====================================================================

INSERT INTO detection_rules (rule_name, rule_description, detection_layer, thresholds, priority, severity, enabled)
VALUES
-- ================================================================
-- Rule 7: Sequence Gap Detection
-- ================================================================
(
    'sequence_gap_large',
    'Detect large gaps in sequence numbers indicating frame injection or spoofing. Normal gaps are 0-4, large gaps suggest injected frames.',
    'LAYER_2',
    JSON_OBJECT(
        'gap_threshold_warn', 50,
        'gap_threshold_alert', 200,
        'gap_threshold_critical', 1000,
        'score_weight', 10,
        'score_formula', 'CASE WHEN gap > 1000 THEN 10 WHEN gap > 200 THEN 7 WHEN gap > 50 THEN 4 ELSE 0 END'
    ),
    85,
    'HIGH',
    1
),
-- ================================================================
-- Rule 8: Sequence Duplicate Detection
-- ================================================================
(
    'sequence_duplicate',
    'Detect duplicate sequence numbers from same source indicating replay attack or frame spoofing.',
    'LAYER_2',
    JSON_OBJECT(
        'duplicate_threshold', 3,
        'window_seconds', 10,
        'score_weight', 12,
        'score_formula', 'min(12, duplicate_count * 4)'
    ),
    88,
    'CRITICAL',
    1
),
-- ================================================================
-- Rule 9: Sequence Pattern Anomaly
-- ================================================================
(
    'sequence_pattern_anomaly',
    'Detect deviation from learned sequence increment patterns. Legitimate devices have consistent patterns, spoofed frames deviate.',
    'LAYER_2',
    JSON_OBJECT(
        'pattern_deviation_threshold', 3.0,
        'min_samples_required', 100,
        'score_weight', 8,
        'score_formula', 'min(8, floor(deviation * 2))'
    ),
    70,
    'MEDIUM',
    1
),
-- ================================================================
-- Rule 10: Sequence Reset Detection
-- ================================================================
(
    'sequence_reset_suspicious',
    'Detect suspicious sequence number resets. Normal resets occur during device reconnection; frequent resets indicate attack.',
    'LAYER_2',
    JSON_OBJECT(
        'max_resets_per_hour', 3,
        'min_frames_between_reset', 100,
        'score_weight', 8,
        'score_formula', 'min(8, (reset_count - 3) * 2)'
    ),
    65,
    'MEDIUM',
    1
),
-- ================================================================
-- Rule 11: Out-of-Order Sequence
-- ================================================================
(
    'sequence_out_of_order',
    'Detect out-of-order sequence numbers indicating multiple sources using same MAC (spoofing).',
    'LAYER_2',
    JSON_OBJECT(
        'ooo_threshold', 5,
        'window_seconds', 5,
        'score_weight', 10,
        'score_formula', 'min(10, ooo_count * 2)'
    ),
    78,
    'HIGH',
    1
);

-- ====================================================================
-- LAYER 3: CONTEXT-BASED DETECTION RULES
-- ====================================================================
-- Purpose: Detect behavioral and temporal anomalies
-- Contribution: Up to 30 points in total score
-- ====================================================================

INSERT INTO detection_rules (rule_name, rule_description, detection_layer, thresholds, priority, severity, enabled)
VALUES
-- ================================================================
-- Rule 12: Time Anomaly Detection
-- ================================================================
(
    'time_anomaly_zscore',
    'Detect deauth activity during statistically unusual times based on historical patterns.',
    'LAYER_3',
    JSON_OBJECT(
        'zscore_threshold_warn', 2.0,
        'zscore_threshold_alert', 3.0,
        'zscore_threshold_critical', 4.0,
        'min_baseline_samples', 168,
        'score_weight', 10,
        'score_formula', 'CASE WHEN zscore > 4 THEN 10 WHEN zscore > 3 THEN 7 WHEN zscore > 2 THEN 4 ELSE 0 END'
    ),
    75,
    'MEDIUM',
    1
),
-- ================================================================
-- Rule 13: Behavioral Deviation
-- ================================================================
(
    'behavioral_deviation',
    'Detect deviation from learned behavioral patterns for MAC/BSSID combinations.',
    'LAYER_3',
    JSON_OBJECT(
        'deviation_threshold_warn', 2.0,
        'deviation_threshold_alert', 3.0,
        'min_baseline_days', 3,
        'score_weight', 8,
        'score_formula', 'min(8, floor(deviation * 2))'
    ),
    70,
    'MEDIUM',
    1
),
-- ================================================================
-- Rule 14: RSSI Anomaly (Proximity)
-- ================================================================
(
    'rssi_jump_detection',
    'Detect sudden RSSI jumps indicating proximity spoofing. Attackers often have different signal characteristics.',
    'LAYER_3',
    JSON_OBJECT(
        'rssi_jump_threshold', 15,
        'window_seconds', 5,
        'score_weight', 6,
        'score_formula', 'min(6, floor(rssi_jump / 10) * 2)'
    ),
    60,
    'MEDIUM',
    1
),
-- ================================================================
-- Rule 15: Client State Correlation
-- ================================================================
(
    'client_state_invalid',
    'Detect deauth frames for clients not in expected session state. Legitimate deauth follows proper state transitions.',
    'LAYER_3',
    JSON_OBJECT(
        'valid_states', JSON_ARRAY('AUTHENTICATED', 'ASSOCIATED'),
        'score_weight', 10,
        'score_formula', 'IF(state_valid, 0, 10)'
    ),
    80,
    'HIGH',
    1
),
-- ================================================================
-- Rule 16: Reason Code Analysis
-- ================================================================
(
    'suspicious_reason_code',
    'Detect suspicious or anomalous 802.11 reason codes. Some reason codes are rarely used legitimately.',
    'LAYER_3',
    JSON_OBJECT(
        'suspicious_codes', JSON_ARRAY(0, 1, 5, 6, 7),
        'rare_codes', JSON_ARRAY(15, 16, 17, 18, 19, 20, 21, 22),
        'score_weight', 5,
        'score_formula', 'CASE WHEN code IN suspicious THEN 5 WHEN code IN rare THEN 3 ELSE 0 END'
    ),
    55,
    'LOW',
    1
),
-- ================================================================
-- Rule 17: Known Attack Tool Fingerprint
-- ================================================================
(
    'attack_tool_fingerprint',
    'Detect patterns matching known attack tools (aireplay-ng, mdk3/4, deauth scripts).',
    'LAYER_3',
    JSON_OBJECT(
        'fingerprints', JSON_OBJECT(
            'aireplay_deauth', JSON_OBJECT(
                'pattern', 'consistent_64_deauth_per_second',
                'reason_code', 7
            ),
            'mdk4_deauth', JSON_OBJECT(
                'pattern', 'random_mac_source',
                'reason_code', 1
            )
        ),
        'score_weight', 15,
        'score_formula', 'IF(fingerprint_match, 15, 0)'
    ),
    95,
    'CRITICAL',
    1
),
-- ================================================================
-- Rule 18: Correlation with Other Events
-- ================================================================
(
    'attack_correlation',
    'Correlate deauth activity with other suspicious events (rogue AP detection, auth failures).',
    'LAYER_3',
    JSON_OBJECT(
        'correlation_window_seconds', 60,
        'correlated_events', JSON_ARRAY('ROGUE_AP', 'AUTH_FAILURE_SPIKE', 'PROBE_FLOOD'),
        'score_weight', 8,
        'score_formula', 'min(8, correlated_count * 4)'
    ),
    75,
    'HIGH',
    1
);

-- ====================================================================
-- COMPOSITE/COMBINED RULES
-- ====================================================================

INSERT INTO detection_rules (rule_name, rule_description, detection_layer, thresholds, priority, severity, enabled)
VALUES
-- ================================================================
-- Rule 19: Evil Twin Attack Pattern
-- ================================================================
(
    'evil_twin_pattern',
    'Detect evil twin attack pattern: deauth + rogue AP with matching SSID. Combines multiple indicators.',
    'ALL',
    JSON_OBJECT(
        'deauth_then_rogue_window_sec', 30,
        'ssid_match_required', true,
        'min_deauth_count', 5,
        'score_weight', 25,
        'score_formula', 'IF(pattern_match, 25, 0)'
    ),
    98,
    'CRITICAL',
    1
),
-- ================================================================
-- Rule 20: Karma/PMKID Attack Pattern
-- ================================================================
(
    'karma_pmkid_pattern',
    'Detect karma/PMKID attack signatures combining deauth with probe response flood.',
    'ALL',
    JSON_OBJECT(
        'probe_flood_threshold', 50,
        'deauth_correlation_window', 10,
        'score_weight', 20,
        'score_formula', 'IF(pattern_match, 20, 0)'
    ),
    96,
    'CRITICAL',
    1
);

-- ====================================================================
-- DEFAULT GLOBAL THRESHOLDS
-- ====================================================================

INSERT INTO detection_thresholds (
    entity_type, entity_id, institute_id,
    l1_deauth_rate_warn, l1_deauth_rate_alert, l1_deauth_rate_critical,
    l1_burst_count_warn, l1_burst_count_alert, l1_burst_count_critical,
    l1_window_seconds,
    l2_seq_gap_warn, l2_seq_gap_alert, l2_seq_gap_critical,
    l2_duplicate_ratio_warn, l2_duplicate_ratio_alert,
    l3_time_zscore_warn, l3_time_zscore_alert, l3_time_zscore_critical,
    l3_behavioral_deviation,
    total_score_warn, total_score_alert, total_score_critical,
    threshold_source
)
VALUES (
    'GLOBAL', NULL, NULL,
    5.00, 10.00, 20.00,
    10, 25, 50,
    5,
    10, 50, 200,
    0.0500, 0.1000,
    2.00, 3.00, 4.00,
    0.2000,
    40, 60, 80,
    'DEFAULT'
);

-- ====================================================================
-- SCORING MATRIX DOCUMENTATION
-- ====================================================================
/*
TOTAL SCORE COMPOSITION (0-100):
================================

Layer 1 (Rate Analysis): 0-40 points
├── deauth_flood_basic:      0-15 points
├── broadcast_deauth_flood:  0-20 points
├── disassoc_flood_basic:    0-12 points
├── single_target_attack:    0-10 points
├── multi_ap_attack:         0-15 points
└── rapid_burst_attack:      0-12 points

Layer 2 (Sequence Analysis): 0-30 points
├── sequence_gap_large:      0-10 points
├── sequence_duplicate:      0-12 points
├── sequence_pattern_anomaly: 0-8 points
├── sequence_reset_suspicious: 0-8 points
└── sequence_out_of_order:   0-10 points

Layer 3 (Context Analysis): 0-30 points
├── time_anomaly_zscore:     0-10 points
├── behavioral_deviation:    0-8 points
├── rssi_jump_detection:     0-6 points
├── client_state_invalid:    0-10 points
├── suspicious_reason_code:  0-5 points
├── attack_tool_fingerprint: 0-15 points
└── attack_correlation:      0-8 points

DECISION THRESHOLDS:
===================
Score 0-39:   BENIGN (no action)
Score 40-59:  WARNING (log and monitor)
Score 60-79:  ALERT (notify admin)
Score 80+:    CRITICAL (auto-block candidate)

ACCURACY TARGETS:
================
True Positive Rate: ≥97%
False Positive Rate: ≤2%
Processing Time: <20ms per frame
Query Response: <3ms
*/

-- ====================================================================
-- VIEW: Active Rules Summary
-- ====================================================================
CREATE OR REPLACE VIEW v_active_rules_summary AS
SELECT 
    detection_layer,
    COUNT(*) as rule_count,
    SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical_rules,
    SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high_rules,
    SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium_rules,
    SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low_rules,
    AVG(priority) as avg_priority
FROM detection_rules
WHERE enabled = 1
GROUP BY detection_layer
ORDER BY FIELD(detection_layer, 'LAYER_1', 'LAYER_2', 'LAYER_3', 'ALL');
