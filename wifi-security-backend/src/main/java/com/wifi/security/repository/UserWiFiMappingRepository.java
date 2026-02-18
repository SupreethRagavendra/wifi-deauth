package com.wifi.security.repository;

import com.wifi.security.entity.User;
import com.wifi.security.entity.UserWiFiMapping;
import com.wifi.security.entity.WiFiNetwork;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for UserWiFiMapping entity operations.
 */
@Repository
public interface UserWiFiMappingRepository extends JpaRepository<UserWiFiMapping, String> {

    /**
     * Find all WiFi mappings for a user.
     */
    List<UserWiFiMapping> findByUser(User user);

    /**
     * Find a specific mapping between user and WiFi network.
     */
    Optional<UserWiFiMapping> findByUserAndWifiNetwork(User user, WiFiNetwork wifiNetwork);

    /**
     * Check if a mapping exists.
     */
    boolean existsByUserAndWifiNetwork(User user, WiFiNetwork wifiNetwork);

    /**
     * Find all mappings for a specific WiFi network.
     */
    List<UserWiFiMapping> findByWifiNetwork(WiFiNetwork wifiNetwork);
}
