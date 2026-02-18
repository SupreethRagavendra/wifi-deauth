package com.wifi.security.entity.detection;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * Entity for baseline MAC statistics used in anomaly detection.
 * 
 * <p>
 * Stores per-MAC address behavioral baselines including rate statistics,
 * sequence patterns, and temporal distributions. Updated every 5 minutes
 * by background aggregation job.
 * </p>
 * 
 * @author WiFi Security Detection Engine
 * @version 1.0.0
 */
@Entity
@Table(name = "baseline_mac_stats", indexes = {
        @Index(name = "idx_baseline_mac", columnList = "mac_address, window_type, window_start DESC"),
        @Index(name = "idx_baseline_bssid", columnList = "bssid, window_type, window_start DESC"),
        @Index(name = "idx_baseline_institute", columnList = "institute_id, window_type, window_start DESC"),
        @Index(name = "idx_baseline_updated", columnList = "updated_at DESC")
}, uniqueConstraints = {
        @UniqueConstraint(name = "uk_mac_bssid_window", columnNames = { "mac_address", "bssid", "window_start",
                "window_type" })
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class BaselineMacStats {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "stat_id")
    private Long statId;

    /**
     * MAC address being tracked.
     */
    @Column(name = "mac_address", nullable = false, length = 17, columnDefinition = "CHAR(17)")
    private String macAddress;

    /**
     * Associated BSSID (one MAC may have multiple BSSID entries).
     */
    @Column(name = "bssid", nullable = false, length = 17, columnDefinition = "CHAR(17)")
    private String bssid;

    /**
     * Institute ID for multi-tenant isolation.
     */
    @Column(name = "institute_id", length = 36)
    private String instituteId;

    /**
     * Time window start.
     */
    @Column(name = "window_start", nullable = false)
    private LocalDateTime windowStart;

    /**
     * Time window end.
     */
    @Column(name = "window_end", nullable = false)
    private LocalDateTime windowEnd;

    /**
     * Window type (granularity).
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "window_type", nullable = false)
    @Builder.Default
    private WindowType windowType = WindowType.HOUR;

    // ================================================================
    // RATE STATISTICS (Layer 1)
    // ================================================================

    @Column(name = "total_frames", nullable = false, columnDefinition = "INT UNSIGNED")
    @Builder.Default
    private Integer totalFrames = 0;

    @Column(name = "deauth_frames", nullable = false, columnDefinition = "INT UNSIGNED")
    @Builder.Default
    private Integer deauthFrames = 0;

    @Column(name = "disassoc_frames", nullable = false, columnDefinition = "INT UNSIGNED")
    @Builder.Default
    private Integer disassocFrames = 0;

    @Column(name = "avg_rate", nullable = false, precision = 10, scale = 4)
    @Builder.Default
    private BigDecimal avgRate = BigDecimal.ZERO;

    @Column(name = "max_rate", nullable = false, precision = 10, scale = 4)
    @Builder.Default
    private BigDecimal maxRate = BigDecimal.ZERO;

    @Column(name = "stddev_rate", nullable = false, precision = 10, scale = 4)
    @Builder.Default
    private BigDecimal stddevRate = BigDecimal.ZERO;

    @Column(name = "p50_rate", precision = 10, scale = 4)
    private BigDecimal p50Rate;

    @Column(name = "p90_rate", precision = 10, scale = 4)
    private BigDecimal p90Rate;

    @Column(name = "p95_rate", precision = 10, scale = 4)
    private BigDecimal p95Rate;

    @Column(name = "p99_rate", precision = 10, scale = 4)
    private BigDecimal p99Rate;

    // ================================================================
    // SEQUENCE STATISTICS (Layer 2)
    // ================================================================

    @Column(name = "avg_seq_gap", precision = 8, scale = 4)
    private BigDecimal avgSeqGap;

    @Column(name = "max_seq_gap", columnDefinition = "INT UNSIGNED")
    private Integer maxSeqGap;

    @Column(name = "seq_anomaly_count", nullable = false, columnDefinition = "INT UNSIGNED")
    @Builder.Default
    private Integer seqAnomalyCount = 0;

    // ================================================================
    // TEMPORAL STATISTICS (Layer 3)
    // ================================================================

    /**
     * 24-element array of frame counts per hour.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "hourly_distribution", columnDefinition = "JSON")
    private int[] hourlyDistribution;

    /**
     * 7-element array for day-of-week distribution.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "daily_distribution", columnDefinition = "JSON")
    private int[] dailyDistribution;

    @Column(name = "first_seen_today")
    private LocalDateTime firstSeenToday;

    @Column(name = "last_seen_today")
    private LocalDateTime lastSeenToday;

    @Column(name = "active_hours", columnDefinition = "TINYINT UNSIGNED")
    @Builder.Default
    private Integer activeHours = 0;

    // ================================================================
    // EXPONENTIAL MOVING AVERAGES (EMA)
    // ================================================================

    @Column(name = "ema_rate", precision = 10, scale = 4)
    private BigDecimal emaRate;

    @Column(name = "ema_seq_gap", precision = 8, scale = 4)
    private BigDecimal emaSeqGap;

    // ================================================================
    // METADATA
    // ================================================================

    @Column(name = "sample_count", nullable = false, columnDefinition = "INT UNSIGNED")
    @Builder.Default
    private Integer sampleCount = 0;

    @Column(name = "confidence_level", nullable = false, precision = 3, scale = 2)
    @Builder.Default
    private BigDecimal confidenceLevel = BigDecimal.ZERO;

    @Column(name = "is_cold_start", nullable = false)
    @Builder.Default
    private Boolean isColdStart = true;

    @Column(name = "created_at", nullable = false, updatable = false, columnDefinition = "DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6)")
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    @Column(name = "updated_at", nullable = false, columnDefinition = "DATETIME(6) DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6)")
    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();

    /**
     * Window type enumeration.
     */
    public enum WindowType {
        HOUR,
        DAY,
        WEEK
    }

    @PrePersist
    protected void onCreate() {
        LocalDateTime now = LocalDateTime.now();
        if (createdAt == null)
            createdAt = now;
        if (updatedAt == null)
            updatedAt = now;
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = LocalDateTime.now();
    }

    /**
     * Calculate Z-score for a given rate.
     */
    public double calculateZScore(double currentRate) {
        if (stddevRate == null || stddevRate.compareTo(BigDecimal.ZERO) == 0) {
            return 0.0;
        }
        return (currentRate - avgRate.doubleValue()) / stddevRate.doubleValue();
    }

    /**
     * Update EMA with new value (alpha = 0.1).
     */
    public void updateEmaRate(double newRate) {
        double alpha = 0.1;
        if (emaRate == null) {
            emaRate = BigDecimal.valueOf(newRate);
        } else {
            double newEma = alpha * newRate + (1 - alpha) * emaRate.doubleValue();
            emaRate = BigDecimal.valueOf(newEma);
        }
    }

    /**
     * Check if baseline has sufficient data for reliable detection.
     */
    public boolean isReliable() {
        return !isColdStart && sampleCount >= 100 &&
                confidenceLevel.compareTo(BigDecimal.valueOf(0.5)) >= 0;
    }
}
