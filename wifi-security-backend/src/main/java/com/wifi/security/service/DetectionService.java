package com.wifi.security.service;

import com.wifi.security.dto.DeauthPacketDTO;
import com.wifi.security.dto.AlertDTO;
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

    private static final long ATTACK_COOLDOWN_MS = 30000; // Attack flag stays for 30s after last packet

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
    private AlertService alertService;

    @Autowired
    private com.wifi.security.repository.PacketRepository packetRepository;

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

        totalPacketCount.addAndGet(validPackets.size());

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
                        entity.setTimestamp(java.time.LocalDateTime.now());
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
                .bssid(packet.getBssid())
                .frameType("DEAUTH")
                .rssi(signalStrength)
                .timestamp(java.time.LocalDateTime.now())
                .build();

        try {
            // Layer 1 Analysis (Synchronous)
            com.wifi.security.dto.response.DetectionResponse response = layer1Service.analyze(request);

            // Layer 2 Analysis (ML) - Only if score >= 40 (according to flowchart)
            if (response.getCombinedScore() >= 40) {
                try {
                    response = layer2Service.analyzeWithML(request, response);
                } catch (Exception e) {
                    logger.warn("Layer 2 ML ignored due to error: {}", e.getMessage());
                }
            }

            // Final Decision
            // If ML says ATTACK (Confidence > 75%), we force trigger
            // OR if Layer 1 score is Suspicious (>= 40) or Attack (>= 75)
            boolean mlConfirmsAttack = response.getMlConfidence() != null && response.getMlConfidence() > 75.0;

            // Allow Suspicious events (>= 40) to trigger the "Under Attack" / "Unsafe"
            // state for visibility
            boolean layer1ConfirmsAttack = response.getCombinedScore() >= suspiciousThreshold;

            if (mlConfirmsAttack || layer1ConfirmsAttack) {
                triggerAttack(packet, response);
            } else {
                broadcastMinorEvent(packet, response);
            }
        } catch (Exception e) {
            logger.error("Error during Analysis: {}", e.getMessage());
        }
    }

    private void triggerAttack(DeauthPacketDTO packet, com.wifi.security.dto.response.DetectionResponse response) {
        long now = System.currentTimeMillis();
        lastAttackTime.set(now);
        boolean wasAlreadyAttacking = underAttack.getAndSet(true);
        totalThreatsDetected.incrementAndGet();

        Map<String, Object> details = new HashMap<>();
        details.put("attackerMac", packet.getSrc());
        details.put("targetBssid", packet.getBssid());
        details.put("packetCount", response.getAnalyzerScores().getRateAnalyzerScore());
        details.put("signal", packet.getSignal());
        details.put("channel", packet.getChannel());
        details.put("reason", packet.getReason());
        details.put("detectedAt", Instant.now().toString());
        details.put("score", response.getCombinedScore());
        details.put("mlConfidence", response.getMlConfidence());
        details.put("layer2Score", response.getLayer2Score());
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
            alert.setMessage(String.format("Attack detected (Score: %d) - Spoofed Source: %s, Network BSSID: %s",
                    response.getCombinedScore(), packet.getSrc(), packet.getBssid()));
            alert.setAttackerMac(packet.getSrc());
            alert.setTargetBssid(packet.getBssid());
            alert.setPacketCount(response.getCombinedScore());
            alert.setSignal(packet.getSignal());
            alert.setChannel(packet.getChannel());
            alert.setTimestamp(Instant.now().toString());

            alertService.processAlert(alert);
            alertService.broadcastStatus(getCurrentStatus());
        } catch (Exception e) {
            logger.error("Failed to process alert: {}", e.getMessage());
        }
    }

    private void broadcastMinorEvent(DeauthPacketDTO packet,
            com.wifi.security.dto.response.DetectionResponse response) {
        try {
            AlertDTO alert = new AlertDTO();
            alert.setType("DEAUTH_PACKET");
            alert.setSeverity(response.getThreatLevel());
            alert.setMessage(String.format("Deauth analyzed (Score: %d) - Source: %s, Network BSSID: %s",
                    response.getCombinedScore(), packet.getSrc(), packet.getBssid()));
            alert.setAttackerMac(packet.getSrc());
            alert.setTargetBssid(packet.getBssid());
            alert.setPacketCount(response.getCombinedScore());
            alert.setSignal(packet.getSignal());
            alert.setChannel(packet.getChannel());
            alert.setTimestamp(Instant.now().toString());

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

        // Filter events within the specified window
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
