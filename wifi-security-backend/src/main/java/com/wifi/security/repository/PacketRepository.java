package com.wifi.security.repository;

import com.wifi.security.entity.CapturedPacket;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;

@Repository
public interface PacketRepository extends JpaRepository<CapturedPacket, String> {

    // Find packets in last N minutes
    @Query("SELECT p FROM CapturedPacket p WHERE p.timestamp >= :since ORDER BY p.timestamp DESC")
    List<CapturedPacket> findRecentPackets(@Param("since") LocalDateTime since);

    // Count packets from specific source MAC
    Long countBySourceMac(String sourceMac);

    // Find packets by BSSID (to link with registered WiFi networks)
    List<CapturedPacket> findByBssid(String bssid);

    @Query("SELECT COUNT(p) FROM CapturedPacket p WHERE p.sourceMac = :sourceMac AND p.bssid = :bssid AND p.timestamp >= :since")
    long countBySourceMacAndBssidAndTimestampAfter(@Param("sourceMac") String sourceMac, @Param("bssid") String bssid,
            @Param("since") LocalDateTime since);

    // Find packets by source MAC and BSSID within time window (for sequence
    // validation)
    @Query("SELECT p FROM CapturedPacket p WHERE p.sourceMac = :sourceMac AND p.bssid = :bssid AND p.timestamp >= :since ORDER BY p.timestamp ASC")
    List<CapturedPacket> findRecentPacketsBySourceAndBssid(@Param("sourceMac") String sourceMac,
            @Param("bssid") String bssid, @Param("since") LocalDateTime since);

    // Find all packets for a BSSID within time window (for session state analysis)
    @Query("SELECT p FROM CapturedPacket p WHERE p.bssid = :bssid AND p.timestamp >= :since ORDER BY p.timestamp ASC")
    List<CapturedPacket> findByBssidAndTimestampAfter(@Param("bssid") String bssid,
            @Param("since") LocalDateTime since);
}
