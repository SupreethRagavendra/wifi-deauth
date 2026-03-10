package com.wifi.security.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * Detection Response DTO containing Layer 1 analysis results.
 * Provides comprehensive detection information including individual analyzer
 * scores.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class DetectionResponse {

    /**
     * Request ID for correlation with original request.
     */
    private String requestId;

    /**
     * Source MAC that was analyzed.
     */
    private String sourceMac;

    /**
     * BSSID of the analyzed network.
     */
    private String bssid;

    /**
     * Destination MAC address of the frame.
     */
    private String destMac;

    /**
     * The real attacker MAC address if spoofed.
     */
    private String realAttackerMac;

    /**
     * Whether the frame is spoofed.
     */
    private Boolean isSpoofed;

    /**
     * Combined weighted score from all analyzers (0-100).
     */
    private int combinedScore;

    /**
     * Threat level classification.
     * Values: NONE, LOW, MEDIUM, HIGH, CRITICAL
     */
    private String threatLevel;

    /**
     * Boolean flag indicating if attack threshold was exceeded.
     */
    private boolean isAttackDetected;

    /**
     * Individual scores from each analyzer.
     */
    private AnalyzerScore analyzerScores;

    /**
     * Timestamp when analysis was performed.
     */
    private LocalDateTime analysisTimestamp;

    /**
     * Processing time in milliseconds.
     */
    private long processingTimeMs;

    /**
     * Detection layer identifier (LAYER_1, LAYER_2, LAYER_3).
     */
    private String layer;

    /**
     * Recommended action based on threat level.
     */
    private String recommendedAction;

    /**
     * Additional metadata or context.
     */
    private String metadata;

    // Layer 2 (ML) Fields
    private Integer dtVote;
    private Integer rfVote;
    private Integer lrVote;
    private Integer xgbVote;
    private Double mlConfidence;
    private Integer layer2Score;

    // Layer 3 Fields
    private Integer layer3Score;
    private String layer3Notes;

    /**
     * ID of the detection event saved to DB by Layer 1, used by Layer 2/3 to update
     * the exact row instead of doing a potentially-racy MAC-based lookup.
     */
    private Long lastSavedEventId;

    /**
     * Sets recommended action based on threat level.
     */
    public void setRecommendedActionFromThreatLevel() {
        if (threatLevel == null) {
            this.recommendedAction = "MONITOR";
            return;
        }

        switch (threatLevel) {
            case "CRITICAL":
                this.recommendedAction = "IMMEDIATE_BLOCK";
                break;
            case "HIGH":
                this.recommendedAction = "ALERT_AND_MONITOR";
                break;
            case "MEDIUM":
                this.recommendedAction = "ENHANCED_MONITORING";
                break;
            case "LOW":
                this.recommendedAction = "LOG_ONLY";
                break;
            default:
                this.recommendedAction = "MONITOR";
        }
    }
}
