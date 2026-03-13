package com.wifi.security.service;

import com.wifi.security.dto.DeauthPacketDTO;
import com.wifi.security.dto.AlertDTO;
import com.wifi.security.dto.response.Layer2Response;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Collectors;
import java.util.stream.Collectors;
import com.wifi.security.dto.AttackAlertData;

@Service
public class DetectionService {

    @org.springframework.scheduling.annotation.Scheduled(fixedRate = 2000)
    public void periodicStatusUpdate() {
        boolean wasAttacking = underAttack.get();
        boolean isAttacking = isUnderAttack(); // This updates the state if timeout occurred

        if (wasAttacking != isAttacking || isAttacking) {
            try {
                alertService.broadcastStatus(getCurrentStatus());
            } catch (Exception e) {
                // Ignore during shutdown
            }
        }
    }

    private static final Logger logger = LoggerFactory.getLogger(DetectionService.class);

    // Configuration
    // Layer 1 Service handles its own thresholds

    private static final long ATTACK_COOLDOWN_MS = 8000; // Flip back to SAFE 8s after last attack packet

    // State
    private final AtomicLong totalThreatsDetected = new AtomicLong(0);
    private final AtomicBoolean underAttack = new AtomicBoolean(false);
    private final AtomicLong totalPacketCount = new AtomicLong(0);
    private final AtomicLong lastAttackTime = new AtomicLong(0);

    @org.springframework.beans.factory.annotation.Value("${detection.layer1.suspicious-threshold:40}")
    private int suspiciousThreshold;

    // Packet tracking
    private final ConcurrentHashMap<String, List<Long>> deauthTimestamps = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<DeauthPacketDTO> recentPackets = new CopyOnWriteArrayList<>();
    private final CopyOnWriteArrayList<Map<String, Object>> attackDetails = new CopyOnWriteArrayList<>();

    @Autowired
    private com.wifi.security.service.layer1.Layer1Service layer1Service;

    @Autowired
    private com.wifi.security.service.layer2.Layer2Service layer2Service;

    @Autowired
    private com.wifi.security.service.layer3.Layer3Service layer3Service;

    @Autowired
    private AlertService alertService;

    @Autowired
    private com.wifi.security.repository.PacketRepository packetRepository;

    @Autowired
    private AlertNotificationService alertNotificationService;

    // ── In-memory burst detector ─────────────────────────────────────────────
    // Tracks deauth timestamps per source MAC to detect rapid bursts
    // that the DB-backed RateAnalyzer misses (batch timing issue)
    private final ConcurrentHashMap<String, List<Long>> burstTimestamps = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Long> lastNotificationTime = new ConcurrentHashMap<>();
    private static final long NOTIFICATION_COOLDOWN_MS = 120_000; // 2 minutes per MAC

    /**
     * Check burst: count deauth packets from this source in the last 2 seconds.
     * Returns a bonus score (0-50) to add to the L1 combined score.
     */
    private int checkBurst(String sourceMac) {
        long now = System.currentTimeMillis();
        long cutoff = now - 2000; // 2 second window

        List<Long> timestamps = burstTimestamps.computeIfAbsent(sourceMac,
                k -> Collections.synchronizedList(new ArrayList<>()));
        timestamps.add(now);

        // Prune old entries
        synchronized (timestamps) {
            timestamps.removeIf(t -> t < cutoff);
        }

        int count = timestamps.size();
        if (count >= 10)
            return 50; // Heavy burst
        if (count >= 5)
            return 40; // Definite burst
        if (count >= 3)
            return 25; // Moderate burst
        return 0;
    }

    // #region agent log
    private void agentLog(String hypothesisId, String location, String message, String jsonData) {
        try {
            String payload = String.format(
                    "{\"sessionId\":\"9afe89\",\"runId\":\"pre-fix-1\",\"hypothesisId\":\"%s\",\"location\":\"%s\",\"message\":\"%s\",\"data\":%s,\"timestamp\":%d}",
                    hypothesisId,
                    location,
                    message.replace("\"", "'"),
                    jsonData != null ? jsonData : "{}",
                    System.currentTimeMillis());

            java.net.URL url = new java.net.URL("http://127.0.0.1:7781/ingest/24b36fd1-0934-4f17-baf9-ad3e553be602");
            java.net.HttpURLConnection conn = (java.net.HttpURLConnection) url.openConnection();
            conn.setRequestMethod("POST");
            conn.setConnectTimeout(500);
            conn.setReadTimeout(500);
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setRequestProperty("X-Debug-Session-Id", "9afe89");

            try (java.io.OutputStream os = conn.getOutputStream()) {
                os.write(payload.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            }
            conn.getResponseCode(); // trigger send
            conn.disconnect();
        } catch (Exception ignored) {
            // Never let debug logging break detection
        }
    }
    // #endregion

    public void processPacket(DeauthPacketDTO packet) {
        processBatch(Collections.singletonList(packet));
    }

    public void processBatch(List<DeauthPacketDTO> packets) {
        if (packets == null || packets.isEmpty())
            return;

        // Filter out test packets
        List<DeauthPacketDTO> validPackets = packets.stream()
                .filter(p -> !p.isTest())
                .collect(Collectors.toList());

        if (validPackets.isEmpty())
            return;

        long newTotal = totalPacketCount.addAndGet(validPackets.size());

        // #region agent log
        agentLog(
                "H1",
                "DetectionService.java:127",
                "Processed deauth batch",
                String.format("{\"batchSize\":%d,\"totalPackets\":%d}", validPackets.size(), newTotal));
        // #endregion

        // Update in-memory recent packets
        recentPackets.addAll(validPackets);
        if (recentPackets.size() > 2000) {
            // Keep only last 1000 to prevent OOM
            recentPackets.subList(0, recentPackets.size() - 1000).clear();
        }

        // 1. Batch Persist to Database (Bulk Insert)
        try {
            List<com.wifi.security.entity.CapturedPacket> entities = validPackets.stream()
                    .map(packet -> {
                        com.wifi.security.entity.CapturedPacket entity = new com.wifi.security.entity.CapturedPacket();
                        entity.setSourceMac(packet.getSrc());
                        entity.setDestMac(packet.getDst());
                        entity.setBssid(packet.getBssid());
                        entity.setSequenceNumber(packet.getSeq());
                        entity.setRssi(packet.getSignal() != null ? packet.getSignal() : -100);
                        entity.setFrameType("DEAUTH");
                        // Use actual capture timestamp from sniffer, not processing time
                        java.time.LocalDateTime capturedAt;
                        try {
                            String ts = packet.getTimestamp();
                            capturedAt = (ts != null && !ts.isEmpty())
                                    ? java.time.LocalDateTime.parse(ts,
                                            java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS"))
                                    : java.time.LocalDateTime.now();
                        } catch (Exception ex) {
                            capturedAt = java.time.LocalDateTime.now();
                        }
                        entity.setTimestamp(capturedAt);
                        return entity;
                    })
                    .collect(Collectors.toList());

            packetRepository.saveAll(entities);
        } catch (Exception e) {
            logger.error("Failed to save batch to DB: {}", e.getMessage());
        }

        // 2. Identify and Analyze Unique Attackers (Optimize: Analyze unique sources
        // only)
        Set<String> uniqueSources = validPackets.stream()
                .map(DeauthPacketDTO::getSrc)
                .filter(Objects::nonNull)
                .collect(Collectors.toSet());

        for (String src : uniqueSources) {
            try {
                // Use the most recent packet from this source for metadata
                DeauthPacketDTO representative = validPackets.stream()
                        .filter(p -> src.equals(p.getSrc()))
                        .reduce((first, second) -> second) // Get last element
                        .orElse(null);

                if (representative != null) {
                    analyzePayload(representative);
                }
            } catch (Exception e) {
                logger.error("Error analyzing source {}: {}", src, e.getMessage());
            }
        }

        // Broadcast updated status (packet counts, etc.) to all SSE clients
        try {
            alertService.broadcastStatus(getCurrentStatus());
        } catch (Exception e) {
            logger.error("Failed to broadcast status after batch: {}", e.getMessage());
        }
    }

    private void analyzePayload(DeauthPacketDTO packet) {
        int signalStrength = packet.getSignal() != null ? packet.getSignal() : -100;

        com.wifi.security.dto.request.DetectionRequest request = com.wifi.security.dto.request.DetectionRequest
                .builder()
                .requestId(java.util.UUID.randomUUID().toString())
                .sourceMac(packet.getSrc())
                .destMac(packet.getDst())
                .bssid(packet.getBssid())
                .frameType("DEAUTH")
                .rssi(signalStrength)
                .isSpoofed(packet.getIsSpoofed())
                .realAttackerMac(packet.getRealAttackerMac())
                .timestamp(java.time.LocalDateTime.now())
                .build();

        try {
            // Layer 1 Analysis (Synchronous)
            com.wifi.security.dto.response.DetectionResponse response = layer1Service.analyze(request);

            // Layer 2 Analysis (ML) - ALWAYS run for deauth frames
            // Previously required L1 score >= 5, but L1 often returns 0 for first packets
            // because DB hasn't accumulated enough data. ML must run to get accurate
            // scores.
            boolean needsML = "DEAUTH".equalsIgnoreCase(request.getFrameType());

            int mlScore = 0;
            String mlPrediction = "SKIPPED";
            double mlConfidence = 0.0;
            String modelAgreement = "0/4";

            if (needsML) {
                try {
                    Layer2Response mlResponse = layer2Service.analyzeWithML(request, response);
                    if (mlResponse != null) {
                        mlScore = mlResponse.getMlScore();
                        mlPrediction = mlResponse.getPrediction();
                        mlConfidence = mlResponse.getConfidence();
                        modelAgreement = mlResponse.getModelAgreement();
                    }
                } catch (Exception e) {
                    logger.warn("Layer 2 ML ignored due to error: {}", e.getMessage());
                }
            }

            // Update Response Payload
            response.setLayer2Score(mlScore);
            response.setMlConfidence(mlConfidence);

            int layer3Score = 0;
            String layer3Notes = null;

            // ALWAYS run Layer 3 analysis for testing
            try {
                com.wifi.security.dto.response.Layer3Response l3 = layer3Service.analyze(packet, response, null);
                layer3Score = l3.getPhysicalScore();
                layer3Notes = l3.getAnalysisNotes();
                response.setLayer3Score(layer3Score);
                response.setLayer3Notes(layer3Notes);
            } catch (Exception e) {
                logger.warn("Layer 3 analysis failed: {}", e.getMessage());
            }

            // Step 4: Calculate final score (L1: 40%, L2: 40%, L3: 20%)
            // L1 gets more weight because ML may not always be available
            double normL1 = Math.min(100.0, (response.getCombinedScore() / 95.0) * 100.0);
            double normL2 = mlScore;
            double normL3 = Math.min(100.0, (layer3Score / 70.0) * 100.0);

            int finalScore = (int) Math.round((normL1 * 0.40) + (normL2 * 0.40) + (normL3 * 0.20));

            // ── Bonuses (capped at +30 total to prevent all events being CRITICAL) ──
            int totalBonus = 0;

            // Burst detection: catches rapid deauths that the DB misses
            int burstBonus = checkBurst(packet.getSrc());
            if (burstBonus > 0) {
                totalBonus += burstBonus;
            }

            // RSSI Score Boost: escalate when RSSI confirms spoofing
            int rssiBoost = packet.getScoreBoost() != null ? packet.getScoreBoost() : 0;
            if (rssiBoost > 0) {
                totalBonus += rssiBoost;
            }

            // Cap total bonuses to prevent inflation
            totalBonus = Math.min(totalBonus, 30);
            if (totalBonus > 0) {
                int preBonus = finalScore;
                finalScore = Math.min(100, finalScore + totalBonus);
                logger.info("⚡ Score bonus: {} + {} = {} (burst={}, rssi={}, source: {})",
                        preBonus, totalBonus, finalScore, burstBonus, rssiBoost, packet.getSrc());
            }

            boolean isDeauth = "DEAUTH".equalsIgnoreCase(request.getFrameType());
            int reason = packet.getReason();
            boolean isNormalDisconnect = isDeauth && (reason == 3 || reason == 8);

            // ── Deauth frame floor (reason-code-aware) ────────────────
            // Normal disconnects (reason 3 = STA leaving, reason 8 = disassociated)
            // should be allowed to score LOW. All other deauth frames get a
            // minimum score of 15 (MEDIUM) since they're suspicious by default.
            if (isDeauth && !isNormalDisconnect) {
                finalScore = Math.max(finalScore, 15);
            }

            // ── Safety floor: use normalized L1 (not raw) ─────────────────
            // Prevents weighted average from dropping below strong L1 signal
            // BUT for normal disconnects we deliberately skip this so they can stay LOW.
            double normL1Floor = Math.min(100.0, (response.getCombinedScore() / 95.0) * 100.0);
            if (!isNormalDisconnect) {
                finalScore = Math.max(finalScore, (int) Math.round(normL1Floor));
            } else {
                // Clamp explicitly into LOW band for clearly benign disconnects
                finalScore = Math.min(finalScore, 10);
            }

            // Recompute threat level based on the final weighted score
            // (the original L1 threat level may be stale after ML & L3 boosting)
            // Unified threat level thresholds (must match Layer1Service +
            // application.properties)
            String updatedThreatLevel;
            if (finalScore >= 50) {
                updatedThreatLevel = "CRITICAL";
            } else if (finalScore >= 30) {
                updatedThreatLevel = "HIGH";
            } else if (finalScore >= 15) {
                updatedThreatLevel = "MEDIUM";
            } else {
                updatedThreatLevel = "LOW";
            }
            response.setThreatLevel(updatedThreatLevel);

            // ALWAYS update the saved detection event with the final weighted score,
            // ML results, and L3 analysis — even if ML was skipped (mlScore=0).
            // This ensures the DB event has the correct totalScore with burst bonus,
            // deauth floor, and RSSI boost applied.
            layer1Service.updateWithMlScores(
                    response.getLastSavedEventId(),
                    packet.getSrc(), mlScore, mlConfidence, mlPrediction, modelAgreement, layer3Score, layer3Notes,
                    finalScore);

            // mlConfidence > 0.60 OR L1 combined score >= 20 triggers attack state
            boolean mlConfirmsAttack = mlConfidence > 0.60;

            // Lower threshold so early-burst packets (before DB window fills)
            // still register as attacks rather than appearing NORMAL
            boolean layer1ConfirmsAttack = response.getCombinedScore() >= 20;

            if (mlConfirmsAttack || layer1ConfirmsAttack) {
                // Ensure trigger uses the newly weighted final score for visibility
                response.setCombinedScore(finalScore);
                triggerAttack(packet, response, mlPrediction, modelAgreement);
            } else if (finalScore >= 10) {
                // Minor events: only update status, do NOT fire SSE alert events
                // Firing alerts for LOW events inflates the frontend threat counter
                response.setCombinedScore(finalScore);
                try {
                    alertService.broadcastStatus(getCurrentStatus());
                } catch (Exception e) {
                    logger.error("Failed to broadcast status for minor event: {}", e.getMessage());
                }
            }
            // score < 10: silently ignored — not an attack, not worth showing
        } catch (Exception e) {
            logger.error("Error during Analysis: {}", e.getMessage());
        }
    }

    private void triggerAttack(DeauthPacketDTO packet, com.wifi.security.dto.response.DetectionResponse response,
            String mlPrediction, String modelAgreement) {
        long now = System.currentTimeMillis();
        lastAttackTime.set(now);
        boolean wasAlreadyAttacking = underAttack.getAndSet(true);

        // Prevent event count inflation by only incrementing when a NEW attack starts
        if (!wasAlreadyAttacking) {
            totalThreatsDetected.incrementAndGet();
        }

        Map<String, Object> details = new HashMap<>();
        details.put("attackerMac", packet.getSrc());
        details.put("targetBssid", packet.getBssid());
        details.put("packetCount",
                response.getAnalyzerScores() != null ? response.getAnalyzerScores().getRateAnalyzerScore() : 0);
        details.put("signal", packet.getSignal());
        details.put("channel", packet.getChannel());
        details.put("reason", packet.getReason());
        details.put("detectedAt", Instant.now().toString());
        details.put("score", response.getCombinedScore());
        details.put("mlConfidence", response.getMlConfidence());
        details.put("mlPrediction", mlPrediction);
        details.put("modelAgreement", modelAgreement);
        details.put("layer2Score", response.getLayer2Score());
        details.put("layer3Score", response.getLayer3Score());
        details.put("layer3Notes", response.getLayer3Notes());
        details.put("threatLevel", response.getThreatLevel());
        details.put("analyzers", response.getAnalyzerScores());

        attackDetails.add(details);
        if (attackDetails.size() > 100) {
            attackDetails.subList(0, 50).clear();
        }

        if (!wasAlreadyAttacking) {
            logger.error("🚨 ALERT: {} Attack (Score: {}) Detected!", response.getThreatLevel(),
                    response.getCombinedScore());
        }

        try {
            AlertDTO alert = new AlertDTO();
            alert.setType("DEAUTH_FLOOD");
            alert.setSeverity(response.getThreatLevel());
            alert.setMessage(String.format(
                    "Attack detected (Score: %d) - Spoofed Source: %s, Network BSSID: %s, Target Client: %s",
                    response.getCombinedScore(), packet.getSrc(), packet.getBssid(), packet.getDst()));
            alert.setAttackerMac(packet.getSrc());
            alert.setTargetBssid(packet.getBssid());
            alert.setTargetMac(packet.getDst());
            alert.setPacketCount(
                    response.getAnalyzerScores() != null
                            ? response.getAnalyzerScores().getRateAnalyzerScore()
                            : 0);
            alert.setScore(response.getCombinedScore());
            alert.setSignal(packet.getSignal());
            alert.setChannel(packet.getChannel());
            alert.setTimestamp(Instant.now().toString());
            alert.setLayer2Score(response.getLayer2Score() != null ? response.getLayer2Score() : 0);
            alert.setLayer3Score(response.getLayer3Score() != null ? response.getLayer3Score() : 0);
            alert.setMlConfidence(response.getMlConfidence());
            alert.setMlPrediction(mlPrediction);
            alert.setModelAgreement(modelAgreement);

            alertService.processAlert(alert);
            alertService.broadcastStatus(getCurrentStatus());

            // ── Send Email/SMS Notifications ────────────────────────────────
            // Only for HIGH/CRITICAL, with rate limiting per source MAC
            if ("CRITICAL".equals(response.getThreatLevel()) || "HIGH".equals(response.getThreatLevel())) {
                try {
                    String srcKey = packet.getSrc() != null ? packet.getSrc() : "unknown";
                    long now2 = System.currentTimeMillis();
                    Long lastSent = lastNotificationTime.get(srcKey);
                    if (lastSent == null || (now2 - lastSent) > NOTIFICATION_COOLDOWN_MS) {
                        lastNotificationTime.put(srcKey, now2);
                        AttackAlertData alertData = AttackAlertData.builder()
                                .attackerMac(packet.getSrc() != null ? packet.getSrc() : "UNKNOWN")
                                .victimMac(packet.getDst() != null ? packet.getDst() : "UNKNOWN")
                                .confidence(response.getMlConfidence() != null
                                        ? response.getMlConfidence() * 100
                                        : (double) response.getCombinedScore())
                                .ssid(packet.getBssid() != null ? packet.getBssid() : "N/A")
                                .timestamp(Instant.now().toString())
                                .defenseLevel(response.getThreatLevel())
                                .channel(packet.getChannel() > 0 ? String.valueOf(packet.getChannel()) : "N/A")
                                .status("detected")
                                .build();
                        alertNotificationService.notifyAttack(alertData.getSsid(), alertData);
                        logger.info("📧 Email/SMS notification sent for attack from {}", srcKey);
                    } else {
                        logger.debug("⏱ Notification rate-limited for {} ({}s remaining)",
                                srcKey, (NOTIFICATION_COOLDOWN_MS - (now2 - lastSent)) / 1000);
                    }
                } catch (Exception notifEx) {
                    logger.error("Failed to send email/SMS notification: {}", notifEx.getMessage());
                }
            }

            // ═══════════════════════════════════════════════════════════════════
            // ATTACK-FOCUSED DEFENSE — Detect the ATTACK, not the ATTACKER
            // ═══════════════════════════════════════════════════════════════════
            // The attacker can change MAC in 1 second. We focus on:
            // - RSSI deviation (physics can't be spoofed)
            // - Deauth rate (attack patterns)
            // - ML confidence (behavioral analysis)
            // Defense actions (PMF, channel hop) are handled by prevention engine.
            // ═══════════════════════════════════════════════════════════════════
            int score = response.getCombinedScore();
            String srcMac = packet.getSrc();
            String dstMac = packet.getDst();
            String bssid = packet.getBssid();

            // Attack detection fields
            String detMethod = packet.getDetectionMethod() != null ? packet.getDetectionMethod() : "NONE";
            boolean isSpoofed = Boolean.TRUE.equals(packet.getIsSpoofed());
            Double rssiDev = packet.getRssiDeviation();
            int attackConf = packet.getAttackerConfidence() != null ? packet.getAttackerConfidence() : 0;

            // Correctly assign attacker and victim logic
            String victimClient;
            String trueAttackerMac;

            if (isSpoofed && packet.getRealAttackerMac() != null
                    && !packet.getRealAttackerMac().equals("00:00:00:00:00:00")) {
                trueAttackerMac = packet.getRealAttackerMac();
                victimClient = srcMac; // Since srcMac was spoofed to be the victim
            } else {
                trueAttackerMac = srcMac;

                // Identify the victim client being disconnected
                if (srcMac != null && bssid != null && srcMac.equalsIgnoreCase(bssid)) {
                    victimClient = dstMac; // AP->Client: dst is victim
                } else {
                    victimClient = dstMac; // Normal assumption if not AP->Client and not known spoof
                }
            }

            if (score >= 85) {
                // ── LEVEL 3 : CRITICAL — Definite attack (LOG ONLY — SSE handled by
                // triggerAttack)
                logger.error("🚨 LEVEL 3 ATTACK CONFIRMED: score={} method={} victim={} BSSID={}",
                        score, detMethod, victimClient, bssid);
            } else if (score >= 60) {
                // ── LEVEL 2 : HIGH — Confirmed attack (LOG ONLY)
                logger.warn("🛡️ LEVEL 2 ATTACK: score={} method={} victim={}",
                        score, detMethod, victimClient);
            } else if (score >= 40) {
                // ── LEVEL 1 : MEDIUM — Suspicious (LOG ONLY)
                logger.info("🔍 Suspicious deauth: score={} on {} — {}",
                        score, bssid, detMethod);
            }
            // score < 40 → silent
        } catch (Exception e) {
            logger.error("Failed to process alert: {}", e.getMessage());
        }
    }

    /** Attempt to enable 802.11w PMF — the only real deauth prevention. */
    private void tryEnablePMF(String bssid) {
        logger.warn("🔒 AUTO-PMF: Requesting 802.11w PMF activation on BSSID {}", bssid);
        AlertDTO pmfAlert = new AlertDTO();
        pmfAlert.setType("PMF_ENABLE");
        pmfAlert.setSeverity("HIGH");
        pmfAlert.setAttackerMac("system");
        pmfAlert.setTargetBssid(bssid);
        pmfAlert.setTimestamp(Instant.now().toString());
        pmfAlert.setMessage(String.format(
                "� Requesting 802.11w PMF on %s to block spoofed deauths", bssid));
        alertService.processAlert(pmfAlert);
    }

    private void broadcastMinorEvent(DeauthPacketDTO packet,
            com.wifi.security.dto.response.DetectionResponse response, String mlPrediction, String modelAgreement) {
        try {
            AlertDTO alert = new AlertDTO();
            alert.setType("DEAUTH_PACKET");
            alert.setSeverity(response.getThreatLevel());
            alert.setMessage(String.format("Deauth analyzed (Score: %d) - Source: %s, Network BSSID: %s",
                    response.getCombinedScore(), packet.getSrc(), packet.getBssid()));
            alert.setAttackerMac(packet.getSrc());
            alert.setTargetBssid(packet.getBssid());
            alert.setTargetMac(packet.getDst());
            alert.setPacketCount(
                    response.getAnalyzerScores() != null
                            ? response.getAnalyzerScores().getRateAnalyzerScore()
                            : 0);
            alert.setScore(response.getCombinedScore());
            alert.setSignal(packet.getSignal());
            alert.setChannel(packet.getChannel());
            alert.setTimestamp(Instant.now().toString());
            alert.setLayer2Score(response.getLayer2Score() != null ? response.getLayer2Score() : 0);
            alert.setLayer3Score(response.getLayer3Score() != null ? response.getLayer3Score() : 0);
            alert.setMlConfidence(response.getMlConfidence());
            alert.setMlPrediction(mlPrediction);
            alert.setModelAgreement(modelAgreement);

            alertService.processAlert(alert);
        } catch (Exception e) {
            logger.error("Failed to process minor alert: {}", e.getMessage());
        }
    }

    public boolean isUnderAttack() {
        // Also check cooldown
        if (underAttack.get()) {
            long now = System.currentTimeMillis();
            if (now - lastAttackTime.get() > ATTACK_COOLDOWN_MS) {
                underAttack.set(false);
                attackDetails.clear();
            }
        }
        return underAttack.get();
    }

    public Map<String, Object> getCurrentStatus() {
        Map<String, Object> status = new HashMap<>();
        boolean attacking = isUnderAttack();

        status.put("status", attacking ? "UNSAFE" : "SAFE");
        status.put("isUnderAttack", attacking);
        status.put("totalPackets", totalPacketCount.get());
        status.put("totalThreats", totalThreatsDetected.get());
        status.put("lastUpdated", Instant.now().toString());

        if (attacking) {
            status.put("attackDetails", getActiveAttackDetails());
        }

        // #region agent log
        agentLog(
                "H2",
                "DetectionService.java:580",
                "getCurrentStatus snapshot",
                String.format(
                        "{\"attacking\":%s,\"totalPackets\":%d,\"totalThreats\":%d}",
                        attacking,
                        totalPacketCount.get(),
                        totalThreatsDetected.get()));
        // #endregion

        return status;
    }

    public List<Map<String, Object>> getActiveAttackDetails() {
        return new ArrayList<>(attackDetails);
    }

    public long getTotalPacketCount() {
        return totalPacketCount.get();
    }

    public Map<String, Object> getStats(int windowSeconds) {
        Map<String, Object> stats = new HashMap<>();

        // Get time-windowed events from Layer1Service
        java.time.LocalDateTime cutoff = java.time.LocalDateTime.now().minusSeconds(windowSeconds);
        java.util.List<com.wifi.security.entity.detection.DetectionEvent> recentEvents = layer1Service
                .getRecentEvents(); // This already gets last 60 seconds

        long windowStart = System.currentTimeMillis() - (windowSeconds * 1000);
        java.util.List<com.wifi.security.entity.detection.DetectionEvent> windowedEvents = recentEvents.stream()
                .filter(e -> e.getDetectedAt().atZone(java.time.ZoneId.systemDefault()).toInstant()
                        .toEpochMilli() >= windowStart)
                .collect(java.util.stream.Collectors.toList());

        stats.put("windowSeconds", windowSeconds);
        stats.put("totalEvents", windowedEvents.size());
        stats.put("criticalEvents", windowedEvents.stream()
                .filter(e -> e.getSeverity() == com.wifi.security.entity.detection.DetectionEvent.Severity.CRITICAL)
                .count());
        stats.put("highEvents", windowedEvents.stream()
                .filter(e -> e.getSeverity() == com.wifi.security.entity.detection.DetectionEvent.Severity.HIGH)
                .count());
        stats.put("mediumEvents", windowedEvents.stream()
                .filter(e -> e.getSeverity() == com.wifi.security.entity.detection.DetectionEvent.Severity.MEDIUM)
                .count());
        stats.put("lowEvents", windowedEvents.stream()
                .filter(e -> e.getSeverity() == com.wifi.security.entity.detection.DetectionEvent.Severity.LOW)
                .count());
        stats.put("isUnderAttack", isUnderAttack());
        stats.put("lastUpdated", java.time.Instant.now().toString());

        return stats;
    }

    public void resetStats() {
        totalPacketCount.set(0);
        lastAttackTime.set(0);
        underAttack.set(false);
        totalThreatsDetected.set(0);
        deauthTimestamps.clear();
        attackDetails.clear();
        recentPackets.clear();
        logger.info("Detection stats reset");
    }
}
