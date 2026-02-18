package com.wifi.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "detected_anomalies")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class DetectedAnomaly {

    @Id
    @Column(name = "anomaly_id")
    private String anomalyId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "scan_id")
    private ScanResult scanResult;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "institute_id", nullable = false)
    private Institute institute;

    @Enumerated(EnumType.STRING)
    @Column(name = "anomaly_type", nullable = false)
    private AnomalyType anomalyType;

    @Column(columnDefinition = "TEXT")
    private String description;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private Severity severity;

    @Column(name = "detected_at")
    @Builder.Default
    private LocalDateTime detectedAt = LocalDateTime.now();

    public enum AnomalyType {
        MISSING_NETWORK,
        ROGUE_AP,
        SIGNAL_DROP,
        SECURITY_MISMATCH
    }

    public enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }
}
