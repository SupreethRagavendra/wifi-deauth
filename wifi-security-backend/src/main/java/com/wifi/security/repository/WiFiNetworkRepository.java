package com.wifi.security.repository;

import com.wifi.security.entity.Institute;
import com.wifi.security.entity.WiFiNetwork;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;

/**
 * Repository for WiFiNetwork entity operations.
 */
@Repository
public interface WiFiNetworkRepository extends JpaRepository<WiFiNetwork, String> {

    /**
     * Find all WiFi networks belonging to an institute.
     */
    List<WiFiNetwork> findByInstitute(Institute institute);

    /**
     * Find all WiFi networks belonging to an institute with createdByUser eagerly
     * fetched.
     */
    @Query("SELECT w FROM WiFiNetwork w LEFT JOIN FETCH w.createdByUser WHERE w.institute = :institute")
    List<WiFiNetwork> findByInstituteWithCreator(@Param("institute") Institute institute);

    /**
     * Check if a BSSID already exists for an institute.
     */
    boolean existsByBssidAndInstitute(String bssid, Institute institute);

    /**
     * Check if ANY registered network has this BSSID — used by prevention to
     * whitelist our own APs (attackers spoof AP MACs in deauth frames).
     */
    boolean existsByBssid(String bssid);

    /**
     * Find the first network matching the given BSSID to extract institute context.
     */
    java.util.Optional<WiFiNetwork> findFirstByBssid(String bssid);
}
