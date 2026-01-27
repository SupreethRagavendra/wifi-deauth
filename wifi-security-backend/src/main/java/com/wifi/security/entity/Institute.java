package com.wifi.security.entity;

import com.wifi.security.enums.InstituteType;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

/**
 * Entity representing an institute (College, School, Company, or Home).
 */
@Entity
@Table(name = "institutes", indexes = {
        @Index(name = "idx_institute_code", columnList = "institute_code")
})
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Institute {

    @Id
    @Column(name = "institute_id", length = 36)
    private String instituteId;

    @Column(name = "institute_name", nullable = false)
    private String instituteName;

    @Enumerated(EnumType.STRING)
    @Column(name = "institute_type", nullable = false)
    private InstituteType instituteType;

    @Column(name = "institute_code", unique = true, length = 20)
    private String instituteCode;

    @Column(name = "location")
    private String location;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;

    @OneToMany(mappedBy = "institute", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<User> users = new ArrayList<>();

    @OneToMany(mappedBy = "institute", cascade = CascadeType.ALL, orphanRemoval = true)
    @Builder.Default
    private List<WiFiNetwork> wifiNetworks = new ArrayList<>();
}
