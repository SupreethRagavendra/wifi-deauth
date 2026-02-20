-- ===================================
-- WiFi Security Platform Database Schema
-- MySQL 8.0+
-- ===================================

-- institutes table
CREATE TABLE IF NOT EXISTS institutes (
    institute_id VARCHAR(36) PRIMARY KEY,
    institute_name VARCHAR(255) NOT NULL,
    institute_type ENUM('HOME', 'COLLEGE', 'SCHOOL', 'COMPANY') NOT NULL,
    institute_code VARCHAR(20) UNIQUE,
    location VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_institute_code (institute_code)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- users table
CREATE TABLE IF NOT EXISTS users (
    user_id VARCHAR(36) PRIMARY KEY,
    institute_id VARCHAR(36),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role ENUM('ADMIN', 'VIEWER', 'HOME_USER') NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (institute_id) REFERENCES institutes(institute_id) ON DELETE CASCADE,
    INDEX idx_email (email),
    INDEX idx_institute_id (institute_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- wifi_networks table (for Module 1, will be used later)
CREATE TABLE IF NOT EXISTS wifi_networks (
    wifi_id VARCHAR(36) PRIMARY KEY,
    institute_id VARCHAR(36) NOT NULL,
    ssid VARCHAR(32) NOT NULL,
    bssid VARCHAR(17) NOT NULL,
    channel INT,
    security_type ENUM('WPA2', 'WPA3', 'OPEN', 'WEP') NOT NULL,
    location VARCHAR(255),
    created_by_user_id VARCHAR(36),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (institute_id) REFERENCES institutes(institute_id) ON DELETE CASCADE,
    FOREIGN KEY (created_by_user_id) REFERENCES users(user_id) ON DELETE SET NULL,
    INDEX idx_wifi_institute_id (institute_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- user_wifi_assignments (for Viewer access control)
CREATE TABLE IF NOT EXISTS user_wifi_assignments (
    mapping_id VARCHAR(36) PRIMARY KEY,
    user_id VARCHAR(36) NOT NULL,
    wifi_id VARCHAR(36) NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (wifi_id) REFERENCES wifi_networks(wifi_id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_wifi (user_id, wifi_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- scan_results table
CREATE TABLE IF NOT EXISTS scan_results (
    scan_id VARCHAR(36) PRIMARY KEY,
    institute_id VARCHAR(36) NOT NULL,
    ssid VARCHAR(32),
    bssid VARCHAR(17) NOT NULL,
    channel INT,
    frequency_band VARCHAR(20),
    rssi INT,
    estimated_distance VARCHAR(50),
    security VARCHAR(50),
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (institute_id) REFERENCES institutes(institute_id) ON DELETE CASCADE,
    INDEX idx_scan_institute (institute_id),
    INDEX idx_scan_bssid (bssid)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- detected_anomalies table
CREATE TABLE IF NOT EXISTS detected_anomalies (
    anomaly_id VARCHAR(36) PRIMARY KEY,
    scan_id VARCHAR(36),
    institute_id VARCHAR(36) NOT NULL,
    anomaly_type ENUM('MISSING_NETWORK', 'ROGUE_AP', 'SIGNAL_DROP', 'SECURITY_MISMATCH') NOT NULL,
    description TEXT,
    severity ENUM('LOW', 'MEDIUM', 'HIGH', 'CRITICAL') NOT NULL,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (scan_id) REFERENCES scan_results(scan_id) ON DELETE SET NULL,
    FOREIGN KEY (institute_id) REFERENCES institutes(institute_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ===================================
-- MODULE 3: Detection Engine Tables
-- ===================================

-- detection_events table - Stores Layer 1 detection results
-- attack_sessions table (Matches AttackSession.java)
CREATE TABLE IF NOT EXISTS attack_sessions (
    session_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    started_at DATETIME(6) NOT NULL,
    ended_at DATETIME(6),
    last_activity DATETIME(6) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',
    attack_type VARCHAR(50) NOT NULL DEFAULT 'UNKNOWN',
    primary_attacker_mac CHAR(17) NOT NULL,
    primary_target_bssid CHAR(17) NOT NULL,
    total_events INT UNSIGNED DEFAULT 0,
    total_frames INT UNSIGNED DEFAULT 0,
    peak_rate DECIMAL(10,2),
    avg_confidence DECIMAL(5,4),
    max_severity VARCHAR(20) DEFAULT 'LOW',
    affected_clients JSON,
    auto_blocked BOOLEAN DEFAULT FALSE,
    blocked_at DATETIME(6),
    block_duration_min INT UNSIGNED,
    institute_id VARCHAR(36),
    analyst_notes TEXT,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    
    INDEX idx_session_status (status, last_activity DESC),
    INDEX idx_session_attacker (primary_attacker_mac, started_at DESC),
    INDEX idx_session_target (primary_target_bssid, started_at DESC),
    INDEX idx_session_institute (institute_id, status, started_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- detection_events table (Updated to match DetectionEvent.java)
CREATE TABLE IF NOT EXISTS detection_events (
    event_id BIGINT AUTO_INCREMENT PRIMARY KEY,
    detected_at DATETIME(6) NOT NULL,
    attack_type VARCHAR(50) NOT NULL,
    confidence DECIMAL(5,4) NOT NULL DEFAULT 0.0000,
    severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
    layer1_score TINYINT UNSIGNED DEFAULT 0,
    layer2_score TINYINT UNSIGNED DEFAULT 0,
    layer3_score TINYINT UNSIGNED DEFAULT 0,
    total_score TINYINT UNSIGNED DEFAULT 0,
    attacker_mac CHAR(17) NOT NULL,
    victim_mac CHAR(17) NOT NULL,
    target_bssid CHAR(17),
    frame_count INT UNSIGNED DEFAULT 0,
    attack_duration_ms INT UNSIGNED DEFAULT 0,
    frames_per_second DECIMAL(10,2),
    attack_start DATETIME(6) NOT NULL,
    attack_end DATETIME(6),
    session_id BIGINT,
    institute_id VARCHAR(36),
    wifi_id VARCHAR(36),
    alert_sent BOOLEAN DEFAULT FALSE,
    blocked BOOLEAN DEFAULT FALSE,
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_by VARCHAR(36),
    acknowledged_at DATETIME(6),
    evidence JSON,
    created_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6),
    updated_at DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    
    FOREIGN KEY (session_id) REFERENCES attack_sessions(session_id) ON DELETE SET NULL,
    FOREIGN KEY (institute_id) REFERENCES institutes(institute_id) ON DELETE CASCADE,
    FOREIGN KEY (wifi_id) REFERENCES wifi_networks(wifi_id) ON DELETE SET NULL,
    
    INDEX idx_event_detected_at (detected_at DESC),
    INDEX idx_event_attacker (attacker_mac, detected_at DESC),
    INDEX idx_event_target (victim_mac, detected_at DESC),
    INDEX idx_event_bssid (target_bssid, detected_at DESC),
    INDEX idx_event_severity (severity, detected_at DESC)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- frame_tracking table - Logs individual frames for analysis
CREATE TABLE IF NOT EXISTS frame_tracking (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    network_id VARCHAR(36),
    source_mac VARCHAR(17) NOT NULL,
    destination_mac VARCHAR(17),
    frame_type VARCHAR(20) NOT NULL,
    sequence_number INT,
    rssi INT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (network_id) REFERENCES wifi_networks(wifi_id) ON DELETE SET NULL,
    INDEX idx_mac_time (source_mac, timestamp),
    INDEX idx_frame_network (network_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- active_sessions table - Tracks connected clients
CREATE TABLE IF NOT EXISTS active_sessions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    network_id VARCHAR(36),
    client_mac VARCHAR(17) NOT NULL,
    associated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_data_frame TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE,
    FOREIGN KEY (network_id) REFERENCES wifi_networks(wifi_id) ON DELETE SET NULL,
    UNIQUE KEY unique_network_client (network_id, client_mac),
    INDEX idx_session_client (client_mac),
    INDEX idx_session_active (is_active)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- network_baselines table - Stores statistical baselines per network/hour
CREATE TABLE IF NOT EXISTS network_baselines (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    network_id VARCHAR(36) NOT NULL,
    hour_of_day INT NOT NULL CHECK (hour_of_day >= 0 AND hour_of_day <= 23),
    avg_deauth_rate DECIMAL(10,4) DEFAULT 0,
    avg_rssi INT DEFAULT -70,
    std_dev DECIMAL(10,4) DEFAULT 1,
    sample_count INT DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (network_id) REFERENCES wifi_networks(wifi_id) ON DELETE CASCADE,
    UNIQUE KEY unique_network_hour (network_id, hour_of_day),
    INDEX idx_baseline_network (network_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

