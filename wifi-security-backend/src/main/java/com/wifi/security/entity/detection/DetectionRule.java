package com.wifi.security.entity.detection;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.Map;

/**
 * Entity for detection rules configuration.
 * 
 * <p>
 * Stores configurable detection rules for the 3-layer detection system.
 * Rules define thresholds, scoring formulas, and severity levels.
 * </p>
 * 
 * @author WiFi Security Detection Engine
 * @version 1.0.0
 */
@Entity
@Table(name = "detection_rules", indexes = {
        @Index(name = "idx_rule_layer", columnList = "detection_layer, enabled")
}, uniqueConstraints = {
        @UniqueConstraint(name = "uk_rule_name", columnNames = { "rule_name" })
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DetectionRule {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rule_id")
    private Long ruleId;

    /**
     * Unique rule name identifier.
     */
    @Column(name = "rule_name", nullable = false, length = 100)
    private String ruleName;

    /**
     * Human-readable rule description.
     */
    @Column(name = "rule_description", nullable = false, columnDefinition = "TEXT")
    private String ruleDescription;

    /**
     * Detection layer this rule belongs to.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "detection_layer", nullable = false)
    private DetectionLayer detectionLayer;

    /**
     * Rule thresholds and parameters (JSON).
     * Contains layer-specific configuration like rates, counts, etc.
     */
    @JdbcTypeCode(SqlTypes.JSON)
    @Column(name = "thresholds", nullable = false, columnDefinition = "JSON")
    private Map<String, Object> thresholds;

    /**
     * Rule priority (0-100, higher = more important).
     */
    @Column(name = "priority", nullable = false, columnDefinition = "TINYINT UNSIGNED")
    @Builder.Default
    private Integer priority = 50;

    /**
     * Default severity when rule triggers.
     */
    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false)
    @Builder.Default
    private DetectionEvent.Severity severity = DetectionEvent.Severity.MEDIUM;

    /**
     * Rule enabled flag.
     */
    @Column(name = "enabled", nullable = false)
    @Builder.Default
    private Boolean enabled = true;

    /**
     * Allow per-institute overrides.
     */
    @Column(name = "allow_override", nullable = false)
    @Builder.Default
    private Boolean allowOverride = true;

    /**
     * Record creation timestamp.
     */
    @Column(name = "created_at", nullable = false, updatable = false)
    @Builder.Default
    private LocalDateTime createdAt = LocalDateTime.now();

    /**
     * Record update timestamp.
     */
    @Column(name = "updated_at", nullable = false)
    @Builder.Default
    private LocalDateTime updatedAt = LocalDateTime.now();

    /**
     * Detection layer enumeration.
     */
    public enum DetectionLayer {
        LAYER_1, // Rate Analysis
        LAYER_2, // Sequence Validation
        LAYER_3, // Context Analysis
        ALL // Composite rules
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
     * Get a threshold value by key.
     */
    @SuppressWarnings("unchecked")
    public <T> T getThreshold(String key, T defaultValue) {
        if (thresholds == null || !thresholds.containsKey(key)) {
            return defaultValue;
        }
        Object value = thresholds.get(key);
        try {
            return (T) value;
        } catch (ClassCastException e) {
            return defaultValue;
        }
    }

    /**
     * Get numeric threshold value.
     */
    public double getNumericThreshold(String key, double defaultValue) {
        Object value = thresholds != null ? thresholds.get(key) : null;
        if (value == null)
            return defaultValue;
        if (value instanceof Number)
            return ((Number) value).doubleValue();
        try {
            return Double.parseDouble(value.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * Get integer threshold value.
     */
    public int getIntThreshold(String key, int defaultValue) {
        return (int) getNumericThreshold(key, defaultValue);
    }

    /**
     * Get score weight for this rule.
     */
    public int getScoreWeight() {
        return getIntThreshold("score_weight", 10);
    }
}
