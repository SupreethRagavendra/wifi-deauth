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

-- user_wifi_mapping (for Viewer access control)
CREATE TABLE IF NOT EXISTS user_wifi_mapping (
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
CREATE TABLE IF NOT EXISTS detection_events (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    network_id VARCHAR(36),
    attacker_mac VARCHAR(17) NOT NULL,
    victim_mac VARCHAR(17) NOT NULL,
    rate_score INT DEFAULT 0,
    sequence_score INT DEFAULT 0,
    time_anomaly_score INT DEFAULT 0,
    session_state_score INT DEFAULT 0,
    layer1_total INT DEFAULT 0,
    final_confidence DECIMAL(5,2),
    verdict VARCHAR(20) NOT NULL,
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    evidence_json JSON,
    FOREIGN KEY (network_id) REFERENCES wifi_networks(wifi_id) ON DELETE SET NULL,
    INDEX idx_detection_network (network_id),
    INDEX idx_detection_attacker (attacker_mac),
    INDEX idx_detection_time (detected_at)
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

