-- ====================================================================
-- WiFi Deauth Attack Detection System - Initial Data & Rules
-- PostgreSQL 14+ Required
-- ====================================================================
-- Seeds default detection rules and test data
-- ====================================================================

-- ====================================================================
-- DEFAULT DETECTION RULES
-- ====================================================================

INSERT INTO detection_rules (rule_name, rule_description, detection_layer, thresholds, priority, severity)
VALUES 
    -- Layer 1: Rate-based detection
    (
        'deauth_flood_threshold',
        'Detect deauthentication flood attacks based on frame rate. Triggers when deauth frames exceed threshold per second.',
        'LAYER_1',
        '{
            "deauth_rate_per_sec": 10,
            "window_seconds": 5,
            "min_frames_trigger": 15
        }'::jsonb,
        90,
        'HIGH'
    ),
    (
        'broadcast_deauth_threshold',
        'Detect broadcast deauth attacks targeting FF:FF:FF:FF:FF:FF. Lower threshold as any broadcast deauth is suspicious.',
        'LAYER_1',
        '{
            "broadcast_rate_per_sec": 3,
            "window_seconds": 5,
            "min_frames_trigger": 5
        }'::jsonb,
        95,
        'CRITICAL'
    ),
    (
        'disassoc_flood_threshold',
        'Detect disassociation flood attacks.',
        'LAYER_1',
        '{
            "disassoc_rate_per_sec": 10,
            "window_seconds": 5,
            "min_frames_trigger": 15
        }'::jsonb,
        85,
        'HIGH'
    ),
    (
        'single_target_attack',
        'Detect attacks targeting a single client MAC address.',
        'LAYER_1',
        '{
            "frames_to_single_target": 10,
            "window_seconds": 10,
            "min_frames_trigger": 10
        }'::jsonb,
        80,
        'HIGH'
    ),
    
    -- Layer 2: Pattern-based detection
    (
        'sequence_gap_anomaly',
        'Detect abnormal sequence number gaps indicating spoofed packets.',
        'LAYER_2',
        '{
            "max_normal_gap": 10,
            "anomaly_threshold": 100,
            "window_seconds": 10,
            "min_gaps_to_trigger": 3
        }'::jsonb,
        75,
        'MEDIUM'
    ),
    (
        'rssi_jump_anomaly',
        'Detect sudden RSSI changes indicating packet injection from different location.',
        'LAYER_2',
        '{
            "rssi_jump_threshold_db": 20,
            "window_seconds": 10,
            "min_jumps_to_trigger": 2
        }'::jsonb,
        70,
        'MEDIUM'
    ),
    (
        'multi_ap_attack',
        'Detect attacks originating from same MAC targeting multiple BSSIDs.',
        'LAYER_2',
        '{
            "min_bssids_attacked": 3,
            "window_minutes": 5,
            "min_frames_per_bssid": 5
        }'::jsonb,
        85,
        'CRITICAL'
    ),
    (
        'client_hopping_pattern',
        'Detect attacker rapidly targeting different clients.',
        'LAYER_2',
        '{
            "min_targets": 5,
            "window_seconds": 30,
            "min_frames_per_target": 2
        }'::jsonb,
        65,
        'MEDIUM'
    ),
    
    -- Layer 3: ML-based detection
    (
        'ml_anomaly_detection',
        'Machine learning model anomaly detection threshold.',
        'LAYER_3',
        '{
            "confidence_threshold": 0.85,
            "min_features_available": 5,
            "model_version": "v1.0"
        }'::jsonb,
        60,
        'HIGH'
    ),
    (
        'behavioral_baseline_deviation',
        'Detect significant deviation from learned baseline behavior.',
        'LAYER_3',
        '{
            "deviation_sigma": 3,
            "baseline_min_age_hours": 24,
            "confidence_threshold": 0.75
        }'::jsonb,
        55,
        'MEDIUM'
    )
ON CONFLICT (rule_name) DO UPDATE SET
    thresholds = EXCLUDED.thresholds,
    updated_at = NOW();

-- ====================================================================
-- DEFAULT REASON CODE MAPPINGS (802.11 standard)
-- ====================================================================

CREATE TABLE IF NOT EXISTS reason_code_mappings (
    reason_code     SMALLINT PRIMARY KEY,
    description     VARCHAR(255) NOT NULL,
    is_malicious    BOOLEAN DEFAULT FALSE,
    notes           TEXT
);

INSERT INTO reason_code_mappings (reason_code, description, is_malicious, notes) VALUES
    (0, 'Reserved', FALSE, 'Not used'),
    (1, 'Unspecified reason', TRUE, 'Often used in attacks, vague'),
    (2, 'Previous authentication no longer valid', FALSE, 'Normal roaming'),
    (3, 'Station leaving BSS (or IBSS)', FALSE, 'Normal disconnect'),
    (4, 'Inactivity timer expired', FALSE, 'Normal idle disconnect'),
    (5, 'AP unable to handle all associated stations', FALSE, 'Normal overload'),
    (6, 'Class 2 frame from non-authenticated station', TRUE, 'May indicate attack'),
    (7, 'Class 3 frame from non-associated station', TRUE, 'Common in attacks'),
    (8, 'Station leaving (or has left) BSS', FALSE, 'Normal'),
    (9, 'Station requesting association not authenticated', FALSE, 'Normal'),
    (10, 'Disassociated due to power capability info', FALSE, 'Normal'),
    (11, 'Disassociated due to supported channels info', FALSE, 'Normal'),
    (12, 'Reserved', FALSE, 'Not used'),
    (13, 'Invalid information element', FALSE, 'Normal error'),
    (14, 'MIC failure', TRUE, 'May indicate key attack'),
    (15, '4-way handshake timeout', TRUE, 'May indicate DOS'),
    (16, 'Group key handshake timeout', TRUE, 'May indicate DOS'),
    (17, 'IE in 4-way handshake different', TRUE, 'May indicate attack'),
    (18, 'Invalid group cipher', FALSE, 'Configuration error'),
    (19, 'Invalid pairwise cipher', FALSE, 'Configuration error'),
    (20, 'Invalid AKMP', FALSE, 'Configuration error'),
    (21, 'Unsupported RSN IE version', FALSE, 'Version mismatch'),
    (22, 'Invalid RSN IE capabilities', FALSE, 'Configuration error'),
    (23, 'IEEE 802.1X authentication failed', FALSE, 'Auth failure'),
    (24, 'Cipher suite rejected due to security policy', FALSE, 'Policy'),
    (25, 'TDLS direct-link teardown unreachable', FALSE, 'TDLS'),
    (26, 'TDLS direct-link teardown unspecified', FALSE, 'TDLS'),
    (27, 'SSP requested disassociation', FALSE, 'Normal'),
    (28, 'No SSP roaming agreement', FALSE, 'Normal'),
    (29, 'Bad cipher or AKM', FALSE, 'Configuration'),
    (30, 'Not authorized for this location', FALSE, 'Policy'),
    (31, 'Service change precludes TS', FALSE, 'QoS change'),
    (32, 'Unspecified QoS reason', FALSE, 'QoS'),
    (33, 'Not enough bandwidth for QoS', FALSE, 'Capacity'),
    (34, 'Missing or poor ACKs', FALSE, 'Link quality'),
    (35, 'Exceeded TXOP limit', FALSE, 'QoS violation'),
    (36, 'STA leaving (or has left)', FALSE, 'Normal'),
    (37, 'End TS / DLS / BA', FALSE, 'Normal'),
    (38, 'Unknown TS / DLS / BA', FALSE, 'Normal'),
    (39, 'Timeout', FALSE, 'Normal'),
    (45, 'Peer link cancelled', FALSE, 'Mesh'),
    (46, 'Mesh max peers reached', FALSE, 'Mesh'),
    (47, 'Mesh config policy violation', FALSE, 'Mesh'),
    (48, 'Mesh close RCVD', FALSE, 'Mesh'),
    (49, 'Mesh max retries', FALSE, 'Mesh'),
    (50, 'Mesh confirm timeout', FALSE, 'Mesh'),
    (51, 'Mesh invalid GTK', FALSE, 'Mesh'),
    (52, 'Mesh inconsistent parameters', FALSE, 'Mesh'),
    (53, 'Mesh invalid security capability', FALSE, 'Mesh'),
    (54, 'Mesh path error: no proxy info', FALSE, 'Mesh'),
    (55, 'Mesh path error: no forwarding info', FALSE, 'Mesh'),
    (56, 'Mesh path error: destination unreachable', FALSE, 'Mesh'),
    (57, 'MAC address exists in MBSS', FALSE, 'Mesh'),
    (58, 'Mesh channel switch: regulatory', FALSE, 'Mesh'),
    (59, 'Mesh channel switch: unspecified', FALSE, 'Mesh')
ON CONFLICT (reason_code) DO NOTHING;

COMMENT ON TABLE reason_code_mappings IS '802.11 reason codes with malicious indicators';

-- ====================================================================
-- OUI VENDOR PREFIXES (Sample - expand as needed)
-- ====================================================================

CREATE TABLE IF NOT EXISTS oui_vendors (
    oui_prefix      VARCHAR(8) PRIMARY KEY,  -- First 3 bytes, e.g., 'AA:BB:CC'
    vendor_name     VARCHAR(255) NOT NULL,
    is_networking   BOOLEAN DEFAULT FALSE,  -- Is this a networking equipment vendor?
    notes           TEXT
);

-- Sample common OUIs
INSERT INTO oui_vendors (oui_prefix, vendor_name, is_networking, notes) VALUES
    ('00:00:5E', 'IANA', FALSE, 'Reserved for IANA'),
    ('00:0C:29', 'VMware', FALSE, 'Virtual machines'),
    ('00:50:56', 'VMware', FALSE, 'Virtual machines'),
    ('08:00:27', 'VirtualBox', FALSE, 'Virtual machines'),
    ('00:1A:2B', 'Cisco', TRUE, 'Networking equipment'),
    ('00:1B:44', 'Cisco', TRUE, 'Networking equipment'),
    ('00:1C:57', 'Cisco', TRUE, 'Networking equipment'),
    ('00:14:22', 'Dell', FALSE, 'Dell computers'),
    ('00:15:5D', 'Microsoft Hyper-V', FALSE, 'Virtual machines'),
    ('00:16:3E', 'Xen', FALSE, 'Virtual machines'),
    ('00:18:0A', 'Cisco', TRUE, 'Networking equipment'),
    ('00:19:D2', 'Intel', FALSE, 'Intel NICs'),
    ('00:1A:A0', 'Dell', FALSE, 'Dell computers'),
    ('00:1B:21', 'Intel', FALSE, 'Intel NICs'),
    ('00:1E:58', 'Compulab', FALSE, 'Embedded systems'),
    ('00:1F:16', 'Nokia', FALSE, 'Nokia devices'),
    ('00:21:5C', 'Intel', FALSE, 'Intel NICs'),
    ('00:23:14', 'Intel', FALSE, 'Intel NICs'),
    ('00:24:D7', 'Intel', FALSE, 'Intel NICs'),
    ('00:25:90', 'Supermicro', TRUE, 'Server equipment'),
    ('00:26:18', 'Cisco', TRUE, 'Networking equipment'),
    ('00:26:B9', 'Dell', FALSE, 'Dell computers'),
    ('00:27:13', 'Intel', FALSE, 'Intel NICs'),
    ('28:D2:44', 'TP-Link', TRUE, 'Consumer routers'),
    ('40:8D:5C', 'GIGA-BYTE', FALSE, 'Motherboards'),
    ('44:D9:E7', 'Cisco', TRUE, 'Networking equipment'),
    ('4C:5E:0C', 'Cisco', TRUE, 'Networking equipment'),
    ('5C:63:BF', 'TP-Link', TRUE, 'Consumer routers'),
    ('60:A4:4C', 'ASUSTek', FALSE, 'ASUS devices'),
    ('64:66:B3', 'Apple', FALSE, 'Apple devices'),
    ('70:85:C2', 'Apple', FALSE, 'Apple devices'),
    ('78:E4:00', 'Apple', FALSE, 'Apple devices'),
    ('80:E6:50', 'Apple', FALSE, 'Apple devices'),
    ('84:38:35', 'Samsung', FALSE, 'Samsung devices'),
    ('88:E9:FE', 'Apple', FALSE, 'Apple devices'),
    ('8C:85:90', 'Apple', FALSE, 'Apple devices'),
    ('98:46:0A', 'Netgear', TRUE, 'Consumer routers'),
    ('9C:D3:6D', 'Netgear', TRUE, 'Consumer routers'),
    ('A0:63:91', 'Netgear', TRUE, 'Consumer routers'),
    ('A4:08:EA', 'Ubiquiti', TRUE, 'Enterprise WiFi'),
    ('A4:91:B1', 'Aruba', TRUE, 'Enterprise WiFi'),
    ('B4:75:0E', 'Belkin', TRUE, 'Consumer routers'),
    ('B8:27:EB', 'Raspberry Pi', FALSE, 'Single board computer'),
    ('C0:4A:00', 'TP-Link', TRUE, 'Consumer routers'),
    ('D0:AB:D5', 'Cisco', TRUE, 'Networking equipment'),
    ('D4:3D:7E', 'D-Link', TRUE, 'Consumer routers'),
    ('DC:A6:32', 'Raspberry Pi', FALSE, 'Single board computer'),
    ('E4:5F:01', 'Ruckus', TRUE, 'Enterprise WiFi'),
    ('EC:FA:BC', 'Aruba', TRUE, 'Enterprise WiFi'),
    ('F0:9F:C2', 'Ubiquiti', TRUE, 'Enterprise WiFi'),
    ('FC:EC:DA', 'Ubiquiti', TRUE, 'Enterprise WiFi'),
    ('FF:FF:FF', 'Broadcast', FALSE, 'Broadcast address')
ON CONFLICT (oui_prefix) DO NOTHING;

COMMENT ON TABLE oui_vendors IS 'OUI vendor lookup for MAC address identification';

-- ====================================================================
-- SAMPLE TEST DATA (for development/testing only)
-- ====================================================================

-- Create a test institute (comment out in production)
-- INSERT INTO test data only for development environments
DO $$
BEGIN
    -- Only insert if we're in a development environment
    -- Check by looking for existing data
    IF NOT EXISTS (SELECT 1 FROM detection_events LIMIT 1) THEN
        RAISE NOTICE 'Database is empty. Skipping test data insertion.';
        RAISE NOTICE 'To insert test data, uncomment the test data section.';
    END IF;
END $$;

-- ====================================================================
-- GRANT PERMISSIONS (adjust role names as needed)
-- ====================================================================

-- Read-only role for dashboard/monitoring
-- CREATE ROLE detection_readonly;
-- GRANT USAGE ON SCHEMA public TO detection_readonly;
-- GRANT SELECT ON ALL TABLES IN SCHEMA public TO detection_readonly;
-- GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO detection_readonly;

-- Application role for detection engine
-- CREATE ROLE detection_app;
-- GRANT USAGE ON SCHEMA public TO detection_app;
-- GRANT SELECT, INSERT, UPDATE ON frame_tracking TO detection_app;
-- GRANT SELECT, INSERT, UPDATE ON detection_events TO detection_app;
-- GRANT SELECT, INSERT, UPDATE ON mac_address_intelligence TO detection_app;
-- GRANT SELECT, INSERT, UPDATE ON blocked_macs TO detection_app;
-- GRANT SELECT ON detection_rules TO detection_app;
-- GRANT SELECT ON baseline_statistics TO detection_app;
-- GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO detection_app;

-- Admin role for maintenance
-- CREATE ROLE detection_admin;
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO detection_admin;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO detection_admin;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO detection_admin;
