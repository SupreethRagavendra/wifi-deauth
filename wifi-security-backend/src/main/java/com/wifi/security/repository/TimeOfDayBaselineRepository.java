package com.wifi.security.repository;

import com.wifi.security.entity.TimeOfDayBaseline;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for time-of-day baseline statistics.
 * 
 * <p>
 * Provides efficient queries for retrieving and updating baseline
 * statistics used in Z-score calculation for time anomaly detection.
 * </p>
 * 
 * @author Algorithm Design Specialist
 * @since 2026-02-07
 */
@Repository
public interface TimeOfDayBaselineRepository extends JpaRepository<TimeOfDayBaseline, Long> {

    /**
     * Finds baseline for a specific network and time slot.
     * 
     * @param bssid     Network BSSID
     * @param dayOfWeek Day of week (0=Mon, 6=Sun)
     * @param hour      Hour (0-23)
     * @return Optional baseline if exists
     */
    Optional<TimeOfDayBaseline> findByBssidAndDayOfWeekAndHour(
            String bssid, Integer dayOfWeek, Integer hour);

    /**
     * Finds all baselines for a specific network.
     * 
     * @param bssid Network BSSID
     * @return List of baselines (up to 168 slots)
     */
    List<TimeOfDayBaseline> findByBssid(String bssid);

    /**
     * Finds all baselines for a network with sufficient samples.
     * 
     * @param bssid      Network BSSID
     * @param minSamples Minimum sample count
     * @return List of statistically valid baselines
     */
    List<TimeOfDayBaseline> findByBssidAndSampleCountGreaterThanEqual(
            String bssid, Integer minSamples);

    /**
     * Calculates global average baseline across all time slots for a network.
     * Used during cold start when specific time slot has insufficient data.
     * 
     * @param bssid Network BSSID
     * @return Optional containing aggregated baseline statistics
     */
    @Query("""
            SELECT new com.wifi.security.entity.TimeOfDayBaseline(
                null,
                b.bssid,
                null,
                0,
                0,
                AVG(b.mean),
                AVG(b.variance),
                AVG(b.stdDev),
                CAST(SUM(b.sampleCount) AS integer),
                MAX(b.lastUpdated),
                MIN(b.createdAt)
            )
            FROM TimeOfDayBaseline b
            WHERE b.bssid = :bssid
            AND b.sampleCount >= 4
            GROUP BY b.bssid
            """)
    Optional<TimeOfDayBaseline> findGlobalAverageByBssid(@Param("bssid") String bssid);

    /**
     * Counts how many time slots have valid baselines for a network.
     * Maximum is 168 (7 days × 24 hours).
     * 
     * @param bssid      Network BSSID
     * @param minSamples Minimum sample count for validity
     * @return Number of valid time slots
     */
    @Query("""
            SELECT COUNT(b)
            FROM TimeOfDayBaseline b
            WHERE b.bssid = :bssid
            AND b.sampleCount >= :minSamples
            """)
    Long countValidSlotsByBssid(
            @Param("bssid") String bssid,
            @Param("minSamples") Integer minSamples);

    /**
     * Finds baselines for a specific day of week (all hours).
     * Useful for day-specific analysis.
     * 
     * @param bssid     Network BSSID
     * @param dayOfWeek Day of week (0-6)
     * @return List of baselines for that day
     */
    List<TimeOfDayBaseline> findByBssidAndDayOfWeek(String bssid, Integer dayOfWeek);

    /**
     * Finds baselines for a specific hour (all days).
     * Useful for hour-specific analysis.
     * 
     * @param bssid Network BSSID
     * @param hour  Hour (0-23)
     * @return List of baselines for that hour
     */
    List<TimeOfDayBaseline> findByBssidAndHour(String bssid, Integer hour);

    /**
     * Deletes all baselines for a network.
     * Used when resetting baselines (e.g., after timezone change).
     * 
     * @param bssid Network BSSID
     */
    void deleteByBssid(String bssid);

    /**
     * Deletes baselines older than specified days (for cleanup).
     * 
     * @param daysOld Number of days since last update
     * @return Number of deleted records
     */
    @Query("""
            DELETE FROM TimeOfDayBaseline b
            WHERE b.lastUpdated < CURRENT_TIMESTAMP - :daysOld DAY
            """)
    int deleteStaleBaselines(@Param("daysOld") Integer daysOld);
}
