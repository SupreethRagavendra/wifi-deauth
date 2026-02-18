-- Add to your existing database

CREATE TABLE IF NOT EXISTS captured_packets (
    id VARCHAR(36) PRIMARY KEY,
    source_mac VARCHAR(17) NOT NULL,
    dest_mac VARCHAR(17) NOT NULL,
    bssid VARCHAR(17),
    sequence_number INT,
    rssi INT,
    timestamp TIMESTAMP NOT NULL,
    frame_type VARCHAR(20),
    received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_source_mac (source_mac),
    INDEX idx_bssid (bssid),
    INDEX idx_timestamp (timestamp)
);
