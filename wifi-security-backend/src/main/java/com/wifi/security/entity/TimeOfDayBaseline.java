package com.wifi.security.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

import java.time.LocalDateTime;

/**
 * Entity representing time-of-day baseline statistics for a network.
 * 
 * <p>
 * Each record stores the statistical baseline for a specific time slot
 * (defined by day_of_week and hour) for a specific BSSID. This enables
 * Z-score calculation to detect unusual activity patterns.
 * </p>
 * 
 * <p>
 * There are 168 unique time slots per BSSID (7 days × 24 hours).
 * </p>
 * 
 * @author Algorithm Design Specialist
 * @since 2026-02-07
 */
@Entity
@Table(name = "time_of_day_baselines", uniqueConstraints = @UniqueConstraint(name = "uk_baseline_slot", columnNames = {
        "bssid", "day_of_week", "hour" }), indexes = {
                @Index(name = "idx_baseline_bssid", columnList = "bssid"),
                @Index(name = "idx_baseline_institute", columnList = "institute_id")
        })
@Data
@NoArgsConstructor
@AllArgsConstructor
public class TimeOfDayBaseline {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "baseline_id")
    private Long id;

    /**
     * Network BSSID (Access Point MAC address).
     * Format: AA:BB:CC:DD:EE:FF
     */
    @Column(name = "bssid", nullable = false, length = 17)
    private String bssid;

    /**
     * Optional association with an institute for multi-tenant support.
     */
    @Column(name = "institute_id", length = 36)
    private String instituteId;

    /**
     * Day of week for this time slot.
     * Values: 0 = Monday, 1 = Tuesday, ..., 6 = Sunday
     */
    @Column(name = "day_of_week", nullable = false)
    private Integer dayOfWeek;

    /**
     * Hour of day for this time slot.
     * Values: 0-23 (24-hour format)
     */
    @Column(name = "hour", nullable = false)
    private Integer hour;

    /**
     * Mean frame rate for this time slot (frames/minute).
     * Calculated using Exponential Moving Average (EMA).
     */
    @Column(name = "mean", nullable = false)
    private Double mean = 0.0;

    /**
     * Variance of frame rate for this time slot.
     * Used for standard deviation calculation.
     */
    @Column(name = "variance", nullable = false)
    private Double variance = 0.0;

    /**
     * Standard deviation of frame rate (σ).
     * Used for Z-score calculation: Z = |X - μ| / σ
     */
    @Column(name = "std_dev", nullable = false)
    private Double stdDev = 2.0;

    /**
     * Number of observations used to build this baseline.
     * Minimum of 4 required for statistical validity.
     */
    @Column(name = "sample_count", nullable = false)
    private Integer sampleCount = 0;

    /**
     * Timestamp of last baseline update.
     */
    @Column(name = "last_updated", nullable = false)
    private LocalDateTime lastUpdated;

    /**
     * Timestamp when this baseline was first created.
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        this.createdAt = LocalDateTime.now();
        this.lastUpdated = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {
        this.lastUpdated = LocalDateTime.now();
    }

    /**
     * Returns the coefficient of variation (CV) for this baseline.
     * CV = σ / μ (useful for comparing variability across different means)
     * 
     * @return Coefficient of variation, or 0 if mean is 0
     */
    @Transient
    public double getCoefficientOfVariation() {
        if (mean == null || mean == 0.0) {
            return 0.0;
        }
        return stdDev / mean;
    }

    /**
     * Checks if this baseline has sufficient samples for reliable detection.
     * 
     * @return true if sample count >= 4
     */
    @Transient
    public boolean isStatisticallyValid() {
        return sampleCount != null && sampleCount >= 4;
    }
}
