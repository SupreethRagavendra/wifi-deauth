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
    security_type ENUM('WPA2', 'WPA3', 'OPEN') NOT NULL,
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
