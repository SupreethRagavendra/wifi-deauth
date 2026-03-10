-- ══════════════════════════════════════════════════════════════
-- Prevention Engine — MySQL Schema (V3)
-- Database: wifi_deauth (Aiven Cloud)
-- ══════════════════════════════════════════════════════════════

-- Session tracking for engine uptime
CREATE TABLE IF NOT EXISTS prevention_session (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    started_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ended_at        DATETIME NULL,
    status          ENUM('running','stopped') NOT NULL DEFAULT 'running',
    active_levels   VARCHAR(64) NOT NULL DEFAULT 'L1',
    notes           TEXT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Main prevention events table (one row per detection event processed)
CREATE TABLE IF NOT EXISTS prevention_events (
    id                      CHAR(36) PRIMARY KEY,
    detection_event_id      CHAR(36) NULL,
    session_id              INT NULL,
    confidence              DECIMAL(5,2) NOT NULL,
    attacker_mac            VARCHAR(17) NOT NULL,
    victim_mac              VARCHAR(17) NOT NULL,
    baseline_latency_ms     DECIMAL(8,2) NULL  COMMENT 'Ping RTT BEFORE optimisation (ms)',
    optimized_latency_ms    DECIMAL(8,2) NULL  COMMENT 'Ping RTT AFTER optimisation (ms)',
    improvement_pct         DECIMAL(5,2) NULL  COMMENT '((baseline - optimized) / baseline) * 100',
    level1_fired            BOOLEAN NOT NULL DEFAULT FALSE,
    level2_fired            BOOLEAN NOT NULL DEFAULT FALSE,
    level3_fired            BOOLEAN NOT NULL DEFAULT FALSE,
    level4_fired            BOOLEAN NOT NULL DEFAULT FALSE,
    components_fired        VARCHAR(200) NULL COMMENT 'Comma-separated component IDs fired',
    honeypot_active         BOOLEAN NOT NULL DEFAULT FALSE,
    forensic_report_path    VARCHAR(500) NULL,
    status                  ENUM('pending','applied','measured','error') NOT NULL DEFAULT 'pending',
    error_msg               TEXT NULL,
    created_at              TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    INDEX idx_created       (created_at),
    INDEX idx_attacker      (attacker_mac),
    INDEX idx_confidence    (confidence),
    FOREIGN KEY (session_id) REFERENCES prevention_session(id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Honeypot activity log
CREATE TABLE IF NOT EXISTS honeypot_log (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    action          ENUM('start','stop') NOT NULL,
    fake_ap_count   INT NOT NULL DEFAULT 150,
    fake_client_count INT NOT NULL DEFAULT 150,
    created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Keep legacy table name as a view for backward compatibility
CREATE OR REPLACE VIEW prevention_level1_events AS
    SELECT
        id, detection_event_id, session_id, confidence,
        attacker_mac, victim_mac,
        baseline_latency_ms   AS baseline_reconnect_ms,
        optimized_latency_ms  AS optimised_reconnect_ms,
        improvement_pct,
        CASE
            WHEN level4_fired THEN 'L1+L2+L3+L4'
            WHEN level3_fired THEN 'L1+L2+L3'
            WHEN level2_fired THEN 'L1+L2'
            ELSE 'L1'
        END AS component_id,
        CASE
            WHEN level4_fired THEN 'Level 1-4 Complete'
            WHEN level3_fired THEN 'Level 1+2+3'
            WHEN level2_fired THEN 'Level 1+2'
            ELSE 'Level 1 Only'
        END AS component_label,
        status, error_msg,
        created_at AS ts
    FROM prevention_events;
