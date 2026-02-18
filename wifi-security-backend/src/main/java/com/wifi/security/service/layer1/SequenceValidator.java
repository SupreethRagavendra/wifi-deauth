package com.wifi.security.service.layer1;

import com.wifi.security.entity.CapturedPacket;
import com.wifi.security.repository.PacketRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.temporal.ChronoUnit;
import java.util.List;

/**
 * SequenceValidator Component for Layer 1 Detection.
 * Validates sequence number patterns in 802.11 frames to detect anomalies.
 * 
 * Key Detection Patterns:
 * - Sequence number resets (indicating spoofed frames)
 * - Duplicate sequence numbers (replay attacks)
 * - Non-sequential jumps (injection attacks)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SequenceValidator {

    private final PacketRepository packetRepository;

    // Scoring constants aligned with RateAnalyzer
    // Scoring constants aligned with RateAnalyzer (0-100 scale)
    private static final int SCORE_NORMAL = 0;
    private static final int SCORE_MINOR_ANOMALY = 40;
    private static final int SCORE_SUSPICIOUS = 70;
    private static final int SCORE_ATTACK = 100;

    // Thresholds for sequence anomaly detection
    private static final int MAX_NORMAL_SEQ_GAP = 10; // Normal gap between sequences
    private static final int MAX_DUPLICATES_ALLOWED = 2; // Allow some duplicates (retransmissions)
    private static final int RESET_THRESHOLD = 3; // Number of resets to trigger alert
    private static final int ANALYSIS_WINDOW_SECONDS = 5;

    /**
     * Validates sequence number patterns for anomalies.
     *
     * @param sourceMac The MAC address of the device sending frames.
     * @param bssid     The BSSID of the target network.
     * @return A risk score based on sequence number analysis.
     */
    public int validate(String sourceMac, String bssid) {
        long startTime = System.nanoTime();

        try {
            LocalDateTime since = LocalDateTime.ofInstant(
                    Instant.now().minus(ANALYSIS_WINDOW_SECONDS, ChronoUnit.SECONDS),
                    ZoneId.systemDefault());

            // Fetch recent packets for this source/bssid combination
            List<CapturedPacket> packets = packetRepository.findRecentPacketsBySourceAndBssid(
                    sourceMac, bssid, since);

            if (packets.isEmpty() || packets.size() < 2) {
                log.debug("Insufficient packets for sequence validation [Source: {}, BSSID: {}]",
                        sourceMac, bssid);
                return SCORE_NORMAL;
            }

            int score = analyzeSequencePatterns(packets);

            if (log.isDebugEnabled()) {
                log.debug("Sequence Validation [Source: {}, BSSID: {}]: {} packets analyzed -> Score: {}",
                        sourceMac, bssid, packets.size(), score);
            }

            return score;

        } catch (Exception e) {
            log.error("Failed to validate sequences for source: {}, bssid: {}", sourceMac, bssid, e);
            return SCORE_NORMAL; // Graceful degradation
        } finally {
            long duration = System.nanoTime() - startTime;
            if (duration > 3_000_000) { // 3ms threshold
                log.warn("Performance Alert: SequenceValidator took {} ns (Source: {})", duration, sourceMac);
            }
        }
    }

    /**
     * Analyzes sequence number patterns in a list of packets.
     */
    private int analyzeSequencePatterns(List<CapturedPacket> packets) {
        int duplicateCount = 0;
        int resetCount = 0;
        int abnormalGapCount = 0;

        Integer previousSeq = null;

        for (CapturedPacket packet : packets) {
            Integer currentSeq = packet.getSequenceNumber();

            if (currentSeq == null) {
                continue;
            }

            if (previousSeq != null) {
                // Check for duplicates
                if (currentSeq.equals(previousSeq)) {
                    duplicateCount++;
                }

                // Check for normal 802.11 sequence wraparound (4095 → 0)
                // This is not suspicious if it's a clean transition
                boolean isNormalWraparound = (previousSeq >= 4090 && currentSeq <= 5);

                // Check for suspicious sequence reset (sequence number suddenly drops)
                // This is different from wraparound - it indicates a spoofed device
                if (!isNormalWraparound && previousSeq > 3000 && currentSeq < 100) {
                    resetCount++;
                }

                // Check for abnormal gaps (excluding normal wraparound)
                int gap = Math.abs(currentSeq - previousSeq);
                // Also check wrapped gap for proper calculation
                int wrappedGap = 4096 - previousSeq + currentSeq;
                int effectiveGap = Math.min(gap, wrappedGap);

                if (effectiveGap > MAX_NORMAL_SEQ_GAP && gap < 4000) { // Avoid false positives on wraparound
                    abnormalGapCount++;
                }
            }

            previousSeq = currentSeq;
        }

        return calculateScore(duplicateCount, resetCount, abnormalGapCount);
    }

    /**
     * Calculates final score based on detected anomalies.
     */
    private int calculateScore(int duplicates, int resets, int abnormalGaps) {
        int totalScore = 0;

        // Excessive duplicates indicate replay attack (lower threshold for detection)
        if (duplicates >= 5) {
            totalScore += SCORE_SUSPICIOUS; // 5+ duplicates is very suspicious
        } else if (duplicates > MAX_DUPLICATES_ALLOWED) {
            totalScore += SCORE_MINOR_ANOMALY;
        }

        // Sequence resets are highly suspicious
        if (resets >= RESET_THRESHOLD) {
            totalScore += SCORE_ATTACK;
        } else if (resets > 0) {
            totalScore += SCORE_SUSPICIOUS;
        }

        // Abnormal gaps indicate injection
        if (abnormalGaps > 5) {
            totalScore += SCORE_SUSPICIOUS;
        } else if (abnormalGaps > 0) {
            totalScore += SCORE_MINOR_ANOMALY;
        }

        // Cap at SCORE_ATTACK to maintain consistent scoring
        return Math.min(totalScore, SCORE_ATTACK);
    }
}
