package com.wifi.security.dto;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@JsonIgnoreProperties(ignoreUnknown = true)
public class AlertDTO {
    private Integer score; // New field for Prevention engine score
    private String type; // DEAUTH_FLOOD, SEQ_ANOMALY, RSSI_ANOMALY
    private String severity; // HIGH, MEDIUM, LOW
    private String message;
    private String attackerMac;
    private String targetBssid;
    private String targetMac;
    private int packetCount;
    private int timeWindow;
    private int seqGap;
    private int lastSeq;
    private int currentSeq;
    private int currentRssi;
    private double averageRssi;
    private double rssiDiff;
    private int signal;
    private int channel;
    private String timestamp;

    // ML Layer fields
    private Integer layer2Score;
    private Integer layer3Score;
    private Double mlConfidence;
    private String mlPrediction;
    private String modelAgreement;

    // Layer 1 Sub-scores
    private Integer rateAnalyzerScore;
    private Integer seqValidatorScore;
    private Integer timeAnomalyScore;
    private Integer sessionStateScore;

    // ── RSSI Attacker Identification fields ──────────────────────────
    private String realAttackerMac;
    private Integer attackerConfidence;
    private String detectionMethod;
    private Boolean isSpoofed;
    private Double rssiDeviation;
}
