package com.wifi.security.service.layer1;

import com.wifi.security.entity.CapturedPacket;
import com.wifi.security.repository.PacketRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * TimeAnomalyDetector Component for Layer 1 Detection.
 * Detects temporal anomalies in frame timing that indicate automated attacks.
 *
 * Key Detection Patterns:
 * - Unusually precise inter-frame intervals (machine-generated)
 * - Burst patterns (many frames in microseconds)
 * - Timestamp inconsistencies
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TimeAnomalyDetector {

    private final PacketRepository packetRepository;

    // Scoring constants
    // Scoring constants (0-100 scale)
    private static final int SCORE_NORMAL = 0;
    private static final int SCORE_MINOR_ANOMALY = 40;
    private static final int SCORE_SUSPICIOUS = 70;
    private static final int SCORE_ATTACK = 100;

    // Temporal analysis thresholds
    private static final long BURST_THRESHOLD_MS = 10; // Frames within 10ms = burst
    private static final int BURST_COUNT_THRESHOLD = 5; // 5+ frames in burst = suspicious
    private static final double TIMING_VARIANCE_THRESHOLD = 0.1; // Very low variance = machine-generated
    private static final int ANALYSIS_WINDOW_SECONDS = 5;

    /**
     * Detects timing anomalies in frame patterns.
     *
     * @param sourceMac The MAC address of the device sending frames.
     * @param bssid     The BSSID of the target network.
     * @return A risk score based on timing analysis.
     */
    public int detectAnomalies(String sourceMac, String bssid) {
        long startTime = System.nanoTime();

        try {
            LocalDateTime since = LocalDateTime.ofInstant(
                    Instant.now().minus(ANALYSIS_WINDOW_SECONDS, ChronoUnit.SECONDS),
                    ZoneId.systemDefault());

            List<CapturedPacket> packets = packetRepository.findRecentPacketsBySourceAndBssid(
                    sourceMac, bssid, since);

            if (packets.size() < 3) {
                log.debug("Insufficient packets for timing analysis [Source: {}, BSSID: {}]",
                        sourceMac, bssid);
                return SCORE_NORMAL;
            }

            int score = analyzeTimingPatterns(packets);

            if (log.isDebugEnabled()) {
                log.debug("Time Anomaly Detection [Source: {}, BSSID: {}]: {} packets -> Score: {}",
                        sourceMac, bssid, packets.size(), score);
            }

            return score;

        } catch (Exception e) {
            log.error("Failed to detect timing anomalies for source: {}, bssid: {}", sourceMac, bssid, e);
            return SCORE_NORMAL;
        } finally {
            long duration = System.nanoTime() - startTime;
            if (duration > 3_000_000) {
                log.warn("Performance Alert: TimeAnomalyDetector took {} ns (Source: {})", duration, sourceMac);
            }
        }
    }

    /**
     * Analyzes timing patterns to detect machine-generated traffic.
     */
    private int analyzeTimingPatterns(List<CapturedPacket> packets) {
        int burstCount = detectBursts(packets);
        double timingVariance = calculateTimingVariance(packets);

        int score = 0;

        // Burst detection
        if (burstCount >= BURST_COUNT_THRESHOLD * 2) {
            score += SCORE_ATTACK;
        } else if (burstCount >= BURST_COUNT_THRESHOLD) {
            score += SCORE_SUSPICIOUS;
        } else if (burstCount > 0) {
            score += SCORE_MINOR_ANOMALY;
        }

        // Machine-generated timing detection (very low variance)
        if (timingVariance >= 0 && timingVariance < TIMING_VARIANCE_THRESHOLD) {
            // Near-zero variance indicates automated tool
            score += SCORE_SUSPICIOUS;
            log.debug("Low timing variance detected: {} (potential automated attack)", timingVariance);
        }

        return Math.min(score, SCORE_ATTACK);
    }

    /**
     * Detects burst patterns in packet timing.
     */
    private int detectBursts(List<CapturedPacket> packets) {
        int burstCount = 0;
        int currentBurst = 0;

        for (int i = 1; i < packets.size(); i++) {
            LocalDateTime prev = packets.get(i - 1).getTimestamp();
            LocalDateTime curr = packets.get(i).getTimestamp();

            if (prev == null || curr == null) {
                continue;
            }

            long intervalMs = Duration.between(prev, curr).toMillis();

            if (intervalMs <= BURST_THRESHOLD_MS) {
                currentBurst++;
            } else {
                if (currentBurst >= BURST_COUNT_THRESHOLD) {
                    burstCount++;
                }
                currentBurst = 0;
            }
        }

        // Check final burst
        if (currentBurst >= BURST_COUNT_THRESHOLD) {
            burstCount++;
        }

        return burstCount;
    }

    /**
     * Calculates variance in inter-frame timing.
     * Low variance indicates machine-generated traffic.
     */
    private double calculateTimingVariance(List<CapturedPacket> packets) {
        if (packets.size() < 3) {
            return -1; // Insufficient data
        }

        double[] intervals = new double[packets.size() - 1];
        int validIntervals = 0;

        for (int i = 1; i < packets.size(); i++) {
            LocalDateTime prev = packets.get(i - 1).getTimestamp();
            LocalDateTime curr = packets.get(i).getTimestamp();

            if (prev != null && curr != null) {
                intervals[validIntervals++] = Duration.between(prev, curr).toNanos();
            }
        }

        if (validIntervals < 2) {
            return -1;
        }

        // Calculate mean
        double sum = 0;
        for (int i = 0; i < validIntervals; i++) {
            sum += intervals[i];
        }
        double mean = sum / validIntervals;

        // Calculate variance
        double varianceSum = 0;
        for (int i = 0; i < validIntervals; i++) {
            varianceSum += Math.pow(intervals[i] - mean, 2);
        }
        double variance = varianceSum / validIntervals;

        // Normalize variance relative to mean for comparison
        if (mean == 0) {
            return 0;
        }
        return Math.sqrt(variance) / mean; // Coefficient of variation
    }
}
