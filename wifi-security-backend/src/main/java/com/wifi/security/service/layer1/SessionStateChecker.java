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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * SessionStateChecker Component for Layer 1 Detection.
 * Verifies deauth frame legitimacy by checking session state context.
 *
 * Key Detection Patterns:
 * - Deauth frames without prior authentication
 * - Deauth to unassociated clients
 * - Multiple simultaneous disconnections (mass deauth)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SessionStateChecker {

    private final PacketRepository packetRepository;

    // Scoring constants
    // Scoring constants (0-100 scale)
    private static final int SCORE_NORMAL = 0;
    private static final int SCORE_MINOR_ANOMALY = 40;
    private static final int SCORE_SUSPICIOUS = 70;
    private static final int SCORE_ATTACK = 100;

    // Session state analysis thresholds - Configurable
    @org.springframework.beans.factory.annotation.Value("${detection.layer1.session.mass-deauth-threshold:10}")
    private int massDeauthThreshold;

    private static final int SESSION_WINDOW_SECONDS = 30; // Longer window for session context

    @org.springframework.beans.factory.annotation.Value("${detection.layer1.session.orphan-deauth-threshold:10}")
    private int orphanDeauthThreshold;

    // Frame types for 802.11
    private static final String FRAME_TYPE_DEAUTH = "DEAUTH";
    private static final String FRAME_TYPE_DISASSOC = "DISASSOC";
    private static final String FRAME_TYPE_AUTH = "AUTH";
    private static final String FRAME_TYPE_ASSOC = "ASSOC";
    private static final String FRAME_TYPE_PROBE = "PROBE";

    /**
     * Checks session state to validate deauth legitimacy.
     *
     * @param sourceMac The MAC address of the device sending deauth.
     * @param bssid     The BSSID of the target network.
     * @return A risk score based on session state analysis.
     */
    public int checkSessionState(String sourceMac, String bssid) {
        long startTime = System.nanoTime();

        try {
            LocalDateTime since = LocalDateTime.ofInstant(
                    Instant.now().minus(SESSION_WINDOW_SECONDS, ChronoUnit.SECONDS),
                    ZoneId.systemDefault());

            // Get all packets in the session window for context
            List<CapturedPacket> packets = packetRepository.findByBssidAndTimestampAfter(bssid, since);

            if (packets.isEmpty()) {
                log.debug("No packets found for session analysis [BSSID: {}]", bssid);
                return SCORE_NORMAL;
            }

            int score = analyzeSessionContext(packets, sourceMac);

            if (log.isDebugEnabled()) {
                log.debug("Session State Check [Source: {}, BSSID: {}]: {} packets -> Score: {}",
                        sourceMac, bssid, packets.size(), score);
            }

            return score;

        } catch (Exception e) {
            log.error("Failed to check session state for source: {}, bssid: {}", sourceMac, bssid, e);
            return SCORE_NORMAL;
        } finally {
            long duration = System.nanoTime() - startTime;
            if (duration > 3_000_000) {
                log.warn("Performance Alert: SessionStateChecker took {} ns (Source: {})", duration, sourceMac);
            }
        }
    }

    /**
     * Analyzes session context for anomalies.
     */
    private int analyzeSessionContext(List<CapturedPacket> packets, String sourceMac) {
        // Track session states per MAC
        Map<String, SessionState> sessionStates = new HashMap<>();
        int orphanDeauthCount = 0;
        int massDeauthVictims = 0;

        for (CapturedPacket packet : packets) {
            String frameType = normalizeFrameType(packet.getFrameType());
            String mac = packet.getSourceMac();

            SessionState state = sessionStates.computeIfAbsent(mac, k -> new SessionState());

            switch (frameType) {
                case FRAME_TYPE_AUTH:
                case FRAME_TYPE_ASSOC:
                case FRAME_TYPE_PROBE:
                    state.setAuthenticated(true);
                    state.setLastActivityTime(packet.getTimestamp());
                    break;

                case FRAME_TYPE_DEAUTH:
                case FRAME_TYPE_DISASSOC:
                    // Check if this is an orphan deauth (no prior auth from this source)
                    if (!state.isAuthenticated() && mac.equals(sourceMac)) {
                        orphanDeauthCount++;
                    }
                    state.incrementDeauthCount();

                    // Track victims of deauth from the source MAC
                    if (mac.equals(sourceMac)) {
                        massDeauthVictims++;
                    }
                    break;
            }
        }

        return calculateScore(orphanDeauthCount, massDeauthVictims, sessionStates.size());
    }

    /**
     * Normalizes frame type strings for comparison.
     */
    private String normalizeFrameType(String frameType) {
        if (frameType == null) {
            return "";
        }
        String upper = frameType.toUpperCase();

        if (upper.contains("DEAUTH"))
            return FRAME_TYPE_DEAUTH;
        if (upper.contains("DISASSOC"))
            return FRAME_TYPE_DISASSOC;
        if (upper.contains("AUTH"))
            return FRAME_TYPE_AUTH;
        if (upper.contains("ASSOC"))
            return FRAME_TYPE_ASSOC;
        if (upper.contains("PROBE"))
            return FRAME_TYPE_PROBE;

        return upper;
    }

    /**
     * Calculates score based on session analysis.
     */
    private int calculateScore(int orphanDeauths, int massDeauthVictims, int uniqueMacs) {
        int score = 0;

        // Orphan deauths (deauth without session context)
        if (orphanDeauths >= orphanDeauthThreshold * 2) {
            score += SCORE_ATTACK;
        } else if (orphanDeauths >= orphanDeauthThreshold) {
            score += SCORE_SUSPICIOUS;
        } else if (orphanDeauths >= 3) {
            score += SCORE_MINOR_ANOMALY;
        }

        // Mass deauth detection
        if (massDeauthVictims >= massDeauthThreshold * 2) {
            score += SCORE_ATTACK;
        } else if (massDeauthVictims >= massDeauthThreshold) {
            score += SCORE_SUSPICIOUS;
        }

        return Math.min(score, SCORE_ATTACK);
    }

    /**
     * Internal class to track session state per MAC.
     */
    private static class SessionState {
        private boolean authenticated = false;
        private LocalDateTime lastActivityTime;
        private int deauthCount = 0;

        public boolean isAuthenticated() {
            return authenticated;
        }

        public void setAuthenticated(boolean authenticated) {
            this.authenticated = authenticated;
        }

        public LocalDateTime getLastActivityTime() {
            return lastActivityTime;
        }

        public void setLastActivityTime(LocalDateTime lastActivityTime) {
            this.lastActivityTime = lastActivityTime;
        }

        public int getDeauthCount() {
            return deauthCount;
        }

        public void incrementDeauthCount() {
            this.deauthCount++;
        }
    }
}
