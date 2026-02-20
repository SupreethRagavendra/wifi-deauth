package com.wifi.security.entity;

import com.wifi.security.enums.SecurityType;
import jakarta.persistence.*;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Entity representing a WiFi network being monitored.
 */
@Entity
@Table(name = "wifi_networks", indexes = {
        @Index(name = "idx_wifi_institute_id", columnList = "institute_id")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class WiFiNetwork {

    @Id
    @Column(name = "wifi_id", columnDefinition = "VARCHAR(36)")
    private String wifiId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "institute_id", nullable = false, columnDefinition = "VARCHAR(36)")
    private Institute institute;

    @Column(name = "ssid", nullable = false, length = 32)
    private String ssid;

    @Pattern(regexp = "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", message = "Invalid MAC address format")
    @Column(name = "bssid", nullable = false, length = 17)
    private String bssid;

    @Column(name = "channel")
    private Integer channel;

    @Enumerated(EnumType.STRING)
    @Column(name = "security_type", nullable = false)
    private SecurityType securityType;

    @Column(name = "location")
    private String location;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "created_by_user_id")
    private User createdByUser;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "wifiNetwork", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<UserWiFiMapping> userMappings = new ArrayList<>();
}
