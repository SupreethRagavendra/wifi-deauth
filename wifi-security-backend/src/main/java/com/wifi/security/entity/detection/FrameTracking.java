package com.wifi.security.entity.detection;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.LocalDateTime;

/**
 * Entity for high-volume frame tracking table.
 * 
 * <p>
 * This table is the core of the detection system, storing all deauth/disassoc
 * frames for real-time analysis. Expected volume: 1000-5000 frames/second.
 * </p>
 * 
 * <p>
 * The table uses MySQL partitioning by date for efficient data lifecycle
 * management with 7-day retention.
 * </p>
 * 
 * @author WiFi Security Detection Engine
 * @version 1.0.0
 */
@Entity
@Table(name = "frame_tracking", indexes = {
        @Index(name = "idx_frame_source_mac_time", columnList = "source_mac, captured_at DESC"),
        @Index(name = "idx_frame_dest_mac_time", columnList = "dest_mac, captured_at DESC"),
        @Index(name = "idx_frame_bssid_time", columnList = "bssid, captured_at DESC"),
        @Index(name = "idx_frame_rate_analysis", columnList = "source_mac, bssid, captured_at DESC"),
        @Index(name = "idx_frame_processing_queue", columnList = "processed, captured_at ASC"),
        @Index(name = "idx_frame_institute", columnList = "institute_id, captured_at DESC")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class FrameTracking {

    /**
     * Primary identifier using BIGINT for high-volume auto-increment.
     * Part of composite primary key with captured_at for partitioning.
     */
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "frame_id")
    private Long frameId;

    /**
     * Timestamp with microsecond precision for frame ordering.
     * Critical for sequence analysis and time-based queries.
     * Part of composite primary key for partitioning support.
     */
    @Column(name = "captured_at", nullable = false, columnDefinition = "DATETIME(6)")
    private LocalDateTime capturedAt;

    /**
     * Source MAC address - origin of the deauth frame.
     * Format: AA:BB:CC:DD:EE:FF
     */
    @Column(name = "source_mac", nullable = false, length = 17, columnDefinition = "CHAR(17)")
    private String sourceMac;

    /**
     * Destination MAC address - target of the deauth.
     * May be broadcast (FF:FF:FF:FF:FF:FF) for broadcast attacks.
     */
    @Column(name = "dest_mac", nullable = false, length = 17, columnDefinition = "CHAR(17)")
    private String destMac;

    /**
     * BSSID - Access point identifier.
     */
    @Column(name = "bssid", nullable = false, length = 17, columnDefinition = "CHAR(17)")
    private String bssid;

    /**
     * Frame type for filtering.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "frame_type", nullable = false)
    @Builder.Default
    private FrameType frameType = FrameType.DEAUTH;

    /**
     * 802.11 Reason code (0-65535).
     */
    @Column(name = "reason_code", nullable = false, columnDefinition = "SMALLINT UNSIGNED")
    @Builder.Default
    private Integer reasonCode = 0;

    /**
     * 802.11 Sequence number (0-4095, 12-bit).
     * Critical for Layer 2 sequence validation.
     */
    @Column(name = "sequence_number", nullable = false, columnDefinition = "SMALLINT UNSIGNED")
    private Integer sequenceNumber;

    /**
     * Signal strength in dBm (-100 to 0).
     * Used for RSSI-based anomaly detection.
     */
    @Column(name = "rssi")
    private Integer rssi;

    /**
     * WiFi channel (1-165).
     */
    @Column(name = "channel", columnDefinition = "TINYINT UNSIGNED")
    private Integer channel;

    /**
     * Reference to WiFi network (nullable for unknown networks).
     */
    @Column(name = "wifi_id", length = 36)
    private String wifiId;

    /**
     * Institute association for multi-tenant support.
     */
    @Column(name = "institute_id", length = 36)
    private String instituteId;

    /**
     * Processing flag - whether analyzed by detection engine.
     */
    @Column(name = "processed", nullable = false)
    @Builder.Default
    private Boolean processed = false;

    /**
     * Layer 1 detection score (0-100).
     */
    @Column(name = "layer1_score", columnDefinition = "TINYINT UNSIGNED")
    private Integer layer1Score;

    /**
     * Layer 2 detection score (0-100).
     */
    @Column(name = "layer2_score", columnDefinition = "TINYINT UNSIGNED")
    private Integer layer2Score;

    /**
     * Layer 3 detection score (0-100).
     */
    @Column(name = "layer3_score", columnDefinition = "TINYINT UNSIGNED")
    private Integer layer3Score;

    /**
     * Record creation timestamp.
     */
    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6)")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    /**
     * Frame type enumeration.
     */
    public enum FrameType {
        DEAUTH,
        DISASSOC,
        AUTH_REJECT,
        ASSOC_REJECT
    }

    /**
     * Pre-persist hook to set timestamps.
     */
    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = LocalDateTime.now();
        }
        if (capturedAt == null) {
            capturedAt = LocalDateTime.now();
        }
    }

    /**
     * Check if this is a broadcast frame.
     */
    public boolean isBroadcast() {
        return "FF:FF:FF:FF:FF:FF".equalsIgnoreCase(destMac);
    }

    /**
     * Calculate combined score from all layers.
     */
    public Integer getTotalScore() {
        int score = 0;
        if (layer1Score != null)
            score += layer1Score;
        if (layer2Score != null)
            score += layer2Score;
        if (layer3Score != null)
            score += layer3Score;
        return score;
    }
}
