package com.wifi.security.entity.detection;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Entity for aggregated attack sessions.
 * 
 * <p>
 * Groups related detection events into cohesive attack sessions
 * for better analysis and response coordination.
 * </p>
 * 
 * @author WiFi Security Detection Engine
 * @version 1.0.0
 */
@Entity
@Table(name = "attack_sessions", indexes = {
        @Index(name = "idx_session_status", columnList = "status, last_activity DESC"),
        @Index(name = "idx_session_attacker", columnList = "primary_attacker_mac, started_at DESC"),
        @Index(name = "idx_session_target", columnList = "primary_target_bssid, started_at DESC"),
        @Index(name = "idx_session_institute", columnList = "institute_id, status, started_at DESC"),
        @Index(name = "idx_session_active", columnList = "status, last_activity DESC")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AttackSession {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "session_id")
    private Long sessionId;

    /**
     * Session start timestamp.
     */
    @Column(name = "started_at", nullable = false, columnDefinition = "DATETIME(6)")
    private LocalDateTime startedAt;

    /**
     * Session end timestamp (NULL if still active).
     */
    @Column(name = "ended_at", columnDefinition = "DATETIME(6)")
    private LocalDateTime endedAt;

    /**
     * Last activity timestamp for session timeout.
     */
    @Column(name = "last_activity", nullable = false, columnDefinition = "DATETIME(6)")
    private LocalDateTime lastActivity;

    /**
     * Session status.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    @Builder.Default
    private SessionStatus status = SessionStatus.ACTIVE;

    /**
     * Attack classification (may evolve during session).
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "attack_type", nullable = false)
    @Builder.Default
    private DetectionEvent.AttackType attackType = DetectionEvent.AttackType.UNKNOWN;

    /**
     * Primary attacker MAC address.
     */
    @Column(name = "primary_attacker_mac", nullable = false, length = 17, columnDefinition = "CHAR(17)")
    private String primaryAttackerMac;

    /**
     * Primary target BSSID.
     */
    @Column(name = "primary_target_bssid", nullable = false, length = 17, columnDefinition = "CHAR(17)")
    private String primaryTargetBssid;

    /**
     * Total detection events in this session.
     */
    @Column(name = "total_events", nullable = false, columnDefinition = "INT UNSIGNED")
    @Builder.Default
    private Integer totalEvents = 0;

    /**
     * Total frames across all events.
     */
    @Column(name = "total_frames", nullable = false, columnDefinition = "INT UNSIGNED")
    @Builder.Default
    private Integer totalFrames = 0;

    /**
     * Peak frame rate (frames/second).
     */
    @Column(name = "peak_rate", precision = 10, scale = 2)
    private BigDecimal peakRate;

    /**
     * Average confidence across events.
     */
    @Column(name = "avg_confidence", precision = 5, scale = 4)
    private BigDecimal avgConfidence;

    /**
     * Maximum severity seen in this session.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "max_severity")
    @Builder.Default
    private DetectionEvent.Severity maxSeverity = DetectionEvent.Severity.LOW;

    /**
     * List of affected client MAC addresses (JSON array).
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "affected_clients", columnDefinition = "JSON")
    private List<String> affectedClients;

    /**
     * Auto-blocking triggered flag.
     */
    @Column(name = "auto_blocked", nullable = false)
    @Builder.Default
    private Boolean autoBlocked = false;

    /**
     * Timestamp when blocking was triggered.
     */
    @Column(name = "blocked_at")
    private LocalDateTime blockedAt;

    /**
     * Block duration in minutes.
     */
    @Column(name = "block_duration_min", columnDefinition = "INT UNSIGNED")
    private Integer blockDurationMin;

    /**
     * Institute ID for multi-tenant support.
     */
    @Column(name = "institute_id", length = 36)
    private String instituteId;

    /**
     * Analyst notes for investigation.
     */
    @Column(name = "analyst_notes", columnDefinition = "TEXT")
    private String analystNotes;

    /**
     * Related detection events.
     */
    @OneToMany(mappedBy = "session", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    @ToString.Exclude
    @EqualsAndHashCode.Exclude
    @com.fasterxml.jackson.annotation.JsonIgnoreProperties("session")
    @Builder.Default
    private List<DetectionEvent> events = new ArrayList<>();

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
     * Session status enumeration.
     */
    public enum SessionStatus {
        ACTIVE,
        ENDED,
        MITIGATED,
        FALSE_POSITIVE
    }

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null)
            createdAt = now;
        if (updatedAt == null)
            updatedAt = now;
        if (startedAt == null)
            startedAt = now;
        if (lastActivity == null)
            lastActivity = now;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * Check if session is currently active.
     */
    public boolean isActive() {
        return status == SessionStatus.ACTIVE;
    }

    /**
     * Calculate session duration in seconds.
     */
    public long getDurationSeconds() {
        LocalDateTime end = endedAt != null ? endedAt : LocalDateTime.now();
        return java.time.Duration.between(startedAt, end).getSeconds();
    }

    /**
     * Add an event to this session and update metrics.
     */
    public void addEvent(DetectionEvent event) {
        if (events == null)
            events = new ArrayList<>();
        events.add(event);
        event.setSession(this);

        totalEvents++;
        totalFrames += event.getFrameCount() != null ? event.getFrameCount() : 0;
        lastActivity = LocalDateTime.now();

        // Update max severity
        if (event.getSeverity() != null &&
                event.getSeverity().ordinal() > maxSeverity.ordinal()) {
            maxSeverity = event.getSeverity();
        }

        // Update peak rate
        if (event.getFramesPerSecond() != null &&
                (peakRate == null || event.getFramesPerSecond().compareTo(peakRate) > 0)) {
            peakRate = event.getFramesPerSecond();
        }
    }

    /**
     * End this session.
     */
    public void endSession() {
        this.status = SessionStatus.ENDED;
        this.endedAt = LocalDateTime.now();
    }

    /**
     * Mark session as mitigated (attack stopped via blocking).
     */
    public void markMitigated() {
        this.status = SessionStatus.MITIGATED;
        this.endedAt = LocalDateTime.now();
    }

    /**
     * Mark session as false positive.
     */
    public void markFalsePositive(String notes) {
        this.status = SessionStatus.FALSE_POSITIVE;
        this.endedAt = LocalDateTime.now();
        this.analystNotes = notes;
    }
}
