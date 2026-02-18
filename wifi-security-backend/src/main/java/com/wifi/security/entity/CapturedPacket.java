package com.wifi.security.entity;

import jakarta.persistence.*;
import lombok.Data;
import java.time.LocalDateTime;

@Entity
@Table(name = "captured_packets", indexes = {
        @Index(name = "idx_source_mac", columnList = "source_mac"),
        @Index(name = "idx_bssid", columnList = "bssid"),
        @Index(name = "idx_timestamp", columnList = "timestamp")
})
@Data
public class CapturedPacket {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(length = 36)
    private String id;

    @Column(name = "source_mac", nullable = false, length = 17)
    private String sourceMac;

    @Column(name = "dest_mac", nullable = false, length = 17)
    private String destMac;

    @Column(name = "bssid", length = 17)
    private String bssid;

    @Column(name = "sequence_number")
    private Integer sequenceNumber;

    @Column(name = "rssi")
    private Integer rssi;

    @Column(name = "timestamp", nullable = false)
    private LocalDateTime timestamp;

    @Column(name = "frame_type", length = 20)
    private String frameType;

    @Column(name = "received_at")
    private LocalDateTime receivedAt;

    @PrePersist
    public void prePersist() {
        this.receivedAt = LocalDateTime.now();
    }
}
