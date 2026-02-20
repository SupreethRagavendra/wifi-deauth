package com.wifi.security.entity.detection;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * Entity for detection events from 3-layer analysis.
 * 
 * <p>
 * Stores detection results including attack classification, confidence scores,
 * and forensic evidence. This is the primary output of the detection engine.
 * </p>
 * 
 * @author WiFi Security Detection Engine
 * @version 1.0.0
 */
@Entity
@Table(name = "detection_events", indexes = {
        @Index(name = "idx_event_detected_at", columnList = "detected_at DESC"),
        @Index(name = "idx_event_attacker", columnList = "attacker_mac, detected_at DESC"),
        @Index(name = "idx_event_target", columnList = "victim_mac, detected_at DESC"),
        @Index(name = "idx_event_bssid", columnList = "target_bssid, detected_at DESC"),
        @Index(name = "idx_event_severity_time", columnList = "severity, detected_at DESC"),
        @Index(name = "idx_event_unack", columnList = "acknowledged, severity DESC, detected_at DESC"),
        @Index(name = "idx_event_session", columnList = "session_id, detected_at"),
        @Index(name = "idx_event_institute", columnList = "institute_id, detected_at DESC"),
        @Index(name = "idx_event_dashboard", columnList = "institute_id, severity, detected_at DESC")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DetectionEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "event_id")
    private Long eventId;

    /**
     * Timestamp of detection.
     */
    @Column(name = "detected_at", nullable = false, columnDefinition = "DATETIME(6)")
    @Builder.Default
    private LocalDateTime detectedAt = LocalDateTime.now();

    /**
     * Attack classification.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "attack_type", nullable = false)
    @Builder.Default
    private AttackType attackType = AttackType.UNKNOWN;

    /**
     * Detection confidence (0.0000 - 1.0000).
     */
    @Column(name = "confidence", nullable = false, precision = 5, scale = 4)
    @Builder.Default
    private BigDecimal confidence = BigDecimal.ZERO;

    /**
     * Severity based on attack impact.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    @Builder.Default
    private Severity severity = Severity.MEDIUM;

    /**
     * Layer 1 (Rate Analysis) score (0-40).
     */
    @Column(name = "layer1_score", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    @Builder.Default
    private Integer layer1Score = 0;

    /**
     * Layer 2 (Sequence Analysis) score (0-30).
     */
    @Column(name = "layer2_score", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    @Builder.Default
    private Integer layer2Score = 0;

    /**
     * Layer 3 (Context Analysis) score (0-30).
     */
    @Column(name = "layer3_score", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    @Builder.Default
    private Integer layer3Score = 0;

    /**
     * Combined score from all layers (0-100).
     */
    @Column(name = "total_score", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    @Builder.Default
    private Integer totalScore = 0;

    /**
     * Suspected attacker MAC address.
     */
    @Column(name = "attacker_mac", nullable = false, length = 17, columnDefinition = "CHAR(17)")
    private String attackerMac;

    /**
     * Target MAC address (NULL for broadcast attacks).
     */
    @Column(name = "victim_mac", nullable = false, length = 17, columnDefinition = "CHAR(17)")
    private String targetMac;

    /**
     * Targeted access point BSSID.
     */
    @Column(name = "target_bssid", length = 17, columnDefinition = "CHAR(17)")
    private String targetBssid;

    /**
     * Number of frames in attack window.
     */
    @Column(name = "frame_count", nullable = false, columnDefinition = "INT UNSIGNED")
    @Builder.Default
    private Integer frameCount = 0;

    /**
     * Attack duration in milliseconds.
     */
    @Column(name = "attack_duration_ms", nullable = false, columnDefinition = "INT UNSIGNED")
    @Builder.Default
    private Integer attackDurationMs = 0;

    /**
     * Attack rate in frames per second.
     */
    @Column(name = "frames_per_second", precision = 10, scale = 2)
    private BigDecimal framesPerSecond;

    /**
     * Attack start timestamp.
     */
    @Column(name = "attack_start", nullable = false, columnDefinition = "DATETIME(6)")
    private LocalDateTime attackStart;

    /**
     * Attack end timestamp (NULL if still active).
     */
    @Column(name = "attack_end", columnDefinition = "DATETIME(6)")
    private LocalDateTime attackEnd;

    /**
     * Reference to attack session for correlated events.
     */
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "session_id")
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties({ "events", "hibernateLazyInitializer", "handler" })
    private AttackSession session;

    /**
     * Institute ID for multi-tenant support.
     */
    @Column(name = "institute_id", length = 36)
    private String instituteId;

    /**
     * WiFi network ID reference.
     */
    @Column(name = "wifi_id", length = 36)
    private String wifiId;

    /**
     * Alert sent flag.
     */
    @Column(name = "alert_sent", nullable = false)
    @Builder.Default
    private Boolean alertSent = false;

    /**
     * Blocked flag (auto-blocking response).
     */
    @Column(name = "blocked", nullable = false)
    @Builder.Default
    private Boolean blocked = false;

    /**
     * Acknowledgement flag.
     */
    @Column(name = "acknowledged", nullable = false)
    @Builder.Default
    private Boolean acknowledged = false;

    /**
     * User ID who acknowledged the event.
     */
    @Column(name = "acknowledged_by", length = 36)
    private String acknowledgedBy;

    /**
     * Acknowledgement timestamp.
     */
    @Column(name = "acknowledged_at")
    private LocalDateTime acknowledgedAt;

    /**
     * Detailed detection evidence (JSON).
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "evidence", columnDefinition = "JSON")
    private Map<String, Object> evidence;

    /**
     * Record creation timestamp.
     */
    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6)")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    /**
     * Record update timestamp.
     */
    @Column(name = "updated_at", nullable = false, columnDefinition = "DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)")
    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();

    /**
     * Attack type enumeration.
     */
    public enum AttackType {
        DEAUTH_FLOOD,
        TARGETED_DEAUTH,
        BROADCAST_DEAUTH,
        ROGUE_AP_DEAUTH,
        DISASSOC_FLOOD,
        KARMA_ATTACK,
        EVIL_TWIN,
        PMKID_ATTACK,
        UNKNOWN
    }

    /**
     * Severity enumeration.
     */
    public enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null)
            createdAt = now;
        if (updatedAt == null)
            updatedAt = now;
        if (detectedAt == null)
            detectedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * Check if this is an active (ongoing) attack.
     */
    public boolean isActive() {
        return attackEnd == null;
    }

    /**
     * Calculate attack duration in seconds.
     */
    public long getAttackDurationSeconds() {
        return attackDurationMs != null ? attackDurationMs / 1000 : 0;
    }

    /**
     * Determine severity from total score.
     */
    public static Severity severityFromScore(int score) {
        if (score >= 80)
            return Severity.CRITICAL;
        if (score >= 60)
            return Severity.HIGH;
        if (score >= 40)
            return Severity.MEDIUM;
        return Severity.LOW;
    }
}
