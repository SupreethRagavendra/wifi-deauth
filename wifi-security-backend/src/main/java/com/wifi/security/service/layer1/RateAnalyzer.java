package com.wifi.security.service.layer1;

import com.wifi.security.repository.PacketRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;

/**
 * RateAnalyzer Component for Layer 1 Detection.
 * Analyzes the frequency of frames (specifically deauth/disassoc) from a
 * specific source
 * within a short time window to detect flooding attacks.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RateAnalyzer {

    private final PacketRepository packetRepository;

    // Scoring constants (0-100 scale)
    private static final int SCORE_NORMAL = 0;
    private static final int SCORE_SLIGHTLY_SUSPICIOUS = 40;
    private static final int SCORE_SUSPICIOUS = 70;
    private static final int SCORE_ATTACK = 100;

    // Thresholds (packets in 5 second window) - Configurable via properties
    @org.springframework.beans.factory.annotation.Value("${detection.layer1.rate.threshold.normal:10}")
    private int thresholdNormal;

    @org.springframework.beans.factory.annotation.Value("${detection.layer1.rate.threshold.suspicious:20}")
    private int thresholdSlightlySuspicious;

    @org.springframework.beans.factory.annotation.Value("${detection.layer1.rate.threshold.attack:50}")
    private int thresholdAttack;

    /**
     * Analyzes Deauth frame rate in the last 5 seconds.
     *
     * @param sourceMac The MAC address of the device sending frames.
     * @param bssid     The BSSID of the network being targeted (used as network
     *                  identifier).
     * @return A risk score based on the frequency of frames.
     */
    public int analyzeRate(String sourceMac, String bssid) {
        long startTime = System.nanoTime();

        try {
            // Time window: Last 5 seconds
            // Note: Converting Instant to LocalDateTime to match Entity field type
            LocalDateTime since = LocalDateTime.ofInstant(
                    Instant.now().minus(5, ChronoUnit.SECONDS),
                    ZoneId.systemDefault());

            // Query repository for frame count efficiently
            // This relies on the composite index (source_mac, bssid, timestamp) in the
            // database
            long frameCount = packetRepository.countBySourceMacAndBssidAndTimestampAfter(sourceMac, bssid, since);

            int score = calculateScore(frameCount);

            if (log.isDebugEnabled()) {
                log.debug("Rate Analysis [Source: {}, BSSID: {}]: {} frames in last 5s -> Score: {}",
                        sourceMac, bssid, frameCount, score);
            }

            return score;

        } catch (Exception e) {
            log.error("Failed to analyze rate for source: {}, bssid: {}", sourceMac, bssid, e);
            // specific exception handling or rethrow could be added here depending on
            // requirements
            // For now, returning 0 to allow system to proceed (graceful degradation)
            return SCORE_NORMAL;
        } finally {
            long duration = System.nanoTime() - startTime;
            // Performance Logging
            // 3ms = 3,000,000 ns. Log warning if threshold exceeded.
            if (duration > 3_000_000) {
                log.warn("Performance Alert: RateAnalyzer took {} ns (Source: {})", duration, sourceMac);
            }
        }
    }

    private int calculateScore(long frameCount) {
        if (frameCount <= thresholdNormal) {
            return SCORE_NORMAL;
        } else if (frameCount <= thresholdSlightlySuspicious) {
            return SCORE_SLIGHTLY_SUSPICIOUS;
        } else if (frameCount <= thresholdAttack) {
            return SCORE_SUSPICIOUS;
        } else {
            return SCORE_ATTACK;
        }
    }
}
