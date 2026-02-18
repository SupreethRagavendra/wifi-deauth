package com.wifi.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

@Entity
@Table(name = "scan_results")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class ScanResult {

    @Id
    @Column(name = "scan_id")
    private String scanId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "institute_id", nullable = false)
    private Institute institute;

    @Column(length = 32)
    private String ssid;

    @Column(nullable = false, length = 17)
    private String bssid;

    private Integer channel;

    @Column(name = "frequency_band", length = 20)
    private String frequencyBand;

    private Integer rssi;

    @Column(name = "estimated_distance", length = 50)
    private String estimatedDistance;

    @Column(length = 50)
    private String security;

    @Column(name = "scanned_at")
    @Builder.Default
    private LocalDateTime scannedAt = LocalDateTime.now();
}
