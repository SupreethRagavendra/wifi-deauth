package com.wifi.security.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;

/**
 * Entity representing the assignment of WiFi networks to Viewer users.
 */
@Entity
@Table(name = "user_wifi_assignments", uniqueConstraints = {
        @UniqueConstraint(name = "unique_user_wifi", columnNames = { "user_id", "wifi_id" })
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserWiFiMapping {

    @Id
    @Column(name = "mapping_id", length = 36)
    private String mappingId;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "wifi_id", nullable = false)
    private WiFiNetwork wifiNetwork;

    @CreationTimestamp
    @Column(name = "assigned_at", updatable = false)
    private LocalDateTime assignedAt;
}
