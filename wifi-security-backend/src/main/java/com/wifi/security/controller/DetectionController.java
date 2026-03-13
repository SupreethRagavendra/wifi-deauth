package com.wifi.security.controller;

import com.wifi.security.dto.AlertDTO;
import com.wifi.security.dto.AttackAlertData;
import com.wifi.security.service.DetectionService;
import com.wifi.security.service.AlertService;
import com.wifi.security.service.layer1.Layer1Service;
import com.wifi.security.entity.detection.DetectionEvent;
import com.wifi.security.repository.DetectionEventRepository;
import com.wifi.security.entity.User;
import com.wifi.security.enums.UserRole;
import com.wifi.security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.LocalDateTime;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/detection")
@CrossOrigin(origins = "*")
public class DetectionController {

    private static final Logger logger = LoggerFactory.getLogger(DetectionController.class);
    private static final AtomicLong eventIdCounter = new AtomicLong(1);

    @Autowired
    private DetectionService detectionService;

    @Autowired
    private AlertService alertService;

    @Autowired
    private Layer1Service layer1Service;

    @Autowired
    private DetectionEventRepository eventRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private com.wifi.security.repository.UserWiFiMappingRepository userWiFiMappingRepository;

    @Autowired
    private com.wifi.security.service.AlertNotificationService alertNotificationService;

    // ─── Helper: get institute ID from JWT ──────────────────────────────────
    private String getCurrentInstituteId() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) {
                return userRepository.findByEmail(auth.getName())
                        .map(u -> u.getInstitute() != null ? u.getInstitute().getInstituteId() : null)
                        .orElse(null);
            }
        } catch (Exception e) {
            logger.warn("Could not extract instituteId from security context: {}", e.getMessage());
        }
        return null;
    }

    @PostMapping("/alert")
    public ResponseEntity<?> receiveAlert(@RequestBody AlertDTO alert) {
        logger.warn("🚨 ALERT RECEIVED: type={} severity={} attacker={}",
                alert.getType(), alert.getSeverity(), alert.getAttackerMac());

        alertService.processAlert(alert);

        // Send email/SMS notifications
        try {
            AttackAlertData alertData = AttackAlertData.builder()
                    .attackerMac(alert.getAttackerMac() != null ? alert.getAttackerMac() : "UNKNOWN")
                    .victimMac(alert.getTargetMac() != null ? alert.getTargetMac() : "UNKNOWN")
                    .confidence(alert.getMlConfidence() != null ? alert.getMlConfidence() * 100
                            : (alert.getScore() != null ? alert.getScore() : 0))
                    .ssid(alert.getTargetBssid() != null ? alert.getTargetBssid() : "N/A")
                    .timestamp(alert.getTimestamp() != null ? alert.getTimestamp()
                            : java.time.LocalDateTime.now().toString())
                    .defenseLevel(alert.getSeverity() != null ? alert.getSeverity() : "LOW")
                    .channel(alert.getChannel() > 0 ? String.valueOf(alert.getChannel()) : "N/A")
                    .status("detected")
                    .build();
            alertNotificationService.notifyAttack(alertData.getSsid(), alertData);
        } catch (Exception e) {
            logger.error("Failed to send attack notifications: {}", e.getMessage());
        }

        return ResponseEntity.ok(Map.of(
                "status", "alert_processed",
                "type", alert.getType()));
    }

    @GetMapping("/live-status")
    public ResponseEntity<?> getLiveStatus() {
        LocalDateTime cutoff30sec = LocalDateTime.now().minusSeconds(30);
        LocalDateTime cutoff1hour = LocalDateTime.now().minusHours(1);

        String instituteId = getCurrentInstituteId();

        List<DetectionEvent> last30sec;
        List<DetectionEvent> lastHour;

        if (instituteId != null) {
            last30sec = eventRepository.findByInstituteIdAndDetectedAtAfter(instituteId, cutoff30sec);
            lastHour = eventRepository.findByInstituteIdAndDetectedAtAfter(instituteId, cutoff1hour);
        } else {
            last30sec = eventRepository.findByDetectedAtAfter(cutoff30sec);
            lastHour = eventRepository.findByDetectedAtAfter(cutoff1hour);
        }

        boolean underAttack = last30sec.stream()
                .anyMatch(e -> e.getSeverity().name().equals("CRITICAL") ||
                        e.getSeverity().name().equals("HIGH") ||
                        e.getSeverity().name().equals("MEDIUM"));

        int activeThreats = (int) last30sec.stream()
                .filter(e -> e.getSeverity().name().equals("CRITICAL") ||
                        e.getSeverity().name().equals("HIGH") ||
                        e.getSeverity().name().equals("MEDIUM"))
                .count();

        int threatsLastHour = (int) lastHour.stream()
                .filter(e -> !e.getSeverity().name().equals("LOW"))
                .count();

        // Severity breakdown for detection monitor (Issue 5)
        long criticalCount = lastHour.stream()
                .filter(e -> e.getSeverity() == DetectionEvent.Severity.CRITICAL).count();
        long highCount = lastHour.stream()
                .filter(e -> e.getSeverity() == DetectionEvent.Severity.HIGH).count();
        long mediumCount = lastHour.stream()
                .filter(e -> e.getSeverity() == DetectionEvent.Severity.MEDIUM).count();
        long lowCount = lastHour.stream()
                .filter(e -> e.getSeverity() == DetectionEvent.Severity.LOW).count();

        Map<String, Object> result = new HashMap<>();
        result.put("systemStatus", underAttack ? "UNSAFE" : "SAFE");
        result.put("activeThreats", activeThreats);
        result.put("threatsLastHour", threatsLastHour);
        result.put("underAttack", underAttack);
        result.put("timestamp", LocalDateTime.now().toString());
        result.put("severityBreakdown", Map.of(
                "critical", criticalCount,
                "high", highCount,
                "medium", mediumCount,
                "low", lowCount,
                "normal", 0));

        // #region agent log
        try {
            String jsonData = String.format(
                    "{\"activeThreats\":%d,\"threatsLastHour\":%d,\"critical\":%d,\"high\":%d,\"medium\":%d,\"low\":%d,\"underAttack\":%s}",
                    activeThreats,
                    threatsLastHour,
                    criticalCount,
                    highCount,
                    mediumCount,
                    lowCount,
                    underAttack);

            String payload = String.format(
                    "{\"sessionId\":\"9afe89\",\"runId\":\"pre-fix-1\",\"hypothesisId\":\"H2\",\"location\":\"DetectionController.java:104\",\"message\":\"live-status computed\",\"data\":%s,\"timestamp\":%d}",
                    jsonData,
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
            conn.getResponseCode();
            conn.disconnect();
        } catch (Exception ignored) {
            // do not break endpoint on debug log failure
        }
        // #endregion

        return ResponseEntity.ok(result);
    }

    @GetMapping("/status")
    public ResponseEntity<?> getDetectionStatus() {
        Map<String, Object> status = new HashMap<>(detectionService.getCurrentStatus());

        // Add real-time threat assessment
        boolean underAttack = layer1Service.isCurrentlyUnderAttack();
        List<DetectionEvent> activeThreats = layer1Service.getActiveThreats();

        status.put("currentlyUnderAttack", underAttack);
        status.put("activeThreats", activeThreats.size());
        status.put("systemStatus", underAttack ? "UNSAFE" : "SAFE");
        status.put("lastChecked", java.time.LocalDateTime.now().toString());

        return ResponseEntity.ok(status);
    }

    @GetMapping("/alerts")
    public ResponseEntity<?> getRecentAlerts() {
        return ResponseEntity.ok(alertService.getRecentAlerts());
    }

    @GetMapping("/alerts/active")
    public ResponseEntity<?> getActiveAlerts() {
        return ResponseEntity.ok(alertService.getActiveAlerts());
    }

    /**
     * Clear all detection stats and alerts (Demo Mode).
     * DELETE /api/detection/events
     */
    @DeleteMapping("/events")
    public ResponseEntity<?> clearDetectionEvents() {
        logger.info("Clearing all detection events and resetting stats");
        alertService.clearAlerts();
        detectionService.resetStats();
        layer1Service.clearAllEvents(); // Clear database events

        // Also reset ML service in-memory counters (fire-and-forget)
        try {
            new RestTemplate().postForObject(
                    "http://localhost:5000/reset-stats", null, String.class);
            logger.info("ML service stats reset successfully");
        } catch (Exception e) {
            logger.warn("Could not reset ML stats (ML service may be offline): {}", e.getMessage());
        }

        return ResponseEntity.ok(Map.of("message", "All detection events cleared"));
    }

    /**
     * Endpoint for frontend: GET /api/detection/events/recent
     * Returns actual DetectionEvent entities from database, scoped to the admin's
     * institute.
     */
    @GetMapping("/events/recent")
    public ResponseEntity<?> getRecentDetectionEvents() {
        logger.debug("Frontend requesting recent detection events");

        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            // If no auth (prevention engine, internal service call), return all recent
            // events
            if (auth == null || auth.getName() == null
                    || "anonymousUser".equals(auth.getName())) {
                List<DetectionEvent> allRecent = layer1Service.getRecentEvents();
                logger.debug("Returning {} events for unauthenticated caller", allRecent.size());
                return ResponseEntity.ok(allRecent != null ? allRecent : List.of());
            }

            com.wifi.security.entity.User user = userRepository.findByEmail(auth.getName()).orElse(null);
            if (user == null) {
                List<DetectionEvent> allRecent = layer1Service.getRecentEvents();
                return ResponseEntity.ok(allRecent != null ? allRecent : List.of());
            }

            String instituteId = user.getInstitute() != null ? user.getInstitute().getInstituteId() : null;

            List<DetectionEvent> events = List.of();
            if (user.getRole() == com.wifi.security.enums.UserRole.VIEWER) {
                // Issue 6: Viewers only see attacks targeting their registered MAC
                String userMac = user.getMacAddress();
                if (userMac != null && !userMac.isEmpty()) {
                    List<String> macs = List.of(userMac.toUpperCase(), userMac.toLowerCase());
                    if (instituteId != null) {
                        events = eventRepository.findTop50ByInstituteIdAndTargetMacInOrderByDetectedAtDesc(
                                instituteId, macs);
                    } else {
                        events = eventRepository.findTop50ByTargetMacInOrderByDetectedAtDesc(macs);
                    }
                    logger.info("Returning {} MAC-filtered events for viewer {} (MAC: {})",
                            events.size(), user.getEmail(), userMac);
                } else {
                    logger.info("Viewer {} has no registered MAC, returning empty", user.getEmail());
                }
            } else {
                // Admin: see all events
                if (instituteId != null) {
                    events = eventRepository.findTop20ByInstituteIdOrderByDetectedAtDesc(instituteId);
                } else {
                    events = layer1Service.getRecentEvents();
                }
                logger.info("Returning {} events for admin {}", events.size(), user.getEmail());
            }

            return ResponseEntity.ok(events != null ? events : List.of());
        } catch (Exception e) {
            logger.error("Error fetching events: {}", e.getMessage());
            return ResponseEntity.ok(List.of());
        }
    }

    private int calculateScore(AlertDTO alert) {
        int score = 0;
        if ("CRITICAL".equals(alert.getSeverity()))
            score = 85;
        else if ("HIGH".equals(alert.getSeverity()))
            score = 70;
        else if ("MEDIUM".equals(alert.getSeverity()))
            score = 40;
        else
            score = 15;

        if (alert.getPacketCount() > 50)
            score += 10;
        else if (alert.getPacketCount() > 20)
            score += 5;

        return Math.min(score, 100);
    }

    private String mapSeverity(String severity) {
        if (severity == null)
            return "LOW";
        return severity;
    }

    @GetMapping("/threat-level")
    public ResponseEntity<?> getCurrentThreatLevel() {
        boolean underAttack = layer1Service.isCurrentlyUnderAttack();
        int activeCount = layer1Service.getActiveThreats().size();

        String level = "SAFE";
        if (activeCount > 10)
            level = "CRITICAL";
        else if (activeCount > 5)
            level = "HIGH";
        else if (activeCount > 0)
            level = "MEDIUM";

        return ResponseEntity.ok(Map.of(
                "threatLevel", level,
                "activeThreats", activeCount,
                "underAttack", underAttack,
                "timestamp", Instant.now().toString()));
    }

    // SSE endpoint for real-time updates to frontend
    @GetMapping(value = "/stream", produces = MediaType.TEXT_EVENT_STREAM_VALUE)
    public SseEmitter streamAlerts() {
        SseEmitter emitter = new SseEmitter(Long.MAX_VALUE);
        alertService.addEmitter(emitter);

        emitter.onCompletion(() -> alertService.removeEmitter(emitter));
        emitter.onTimeout(() -> alertService.removeEmitter(emitter));
        emitter.onError(e -> alertService.removeEmitter(emitter));

        // Send current status immediately
        try {
            emitter.send(SseEmitter.event()
                    .name("status")
                    .data(getDetectionStatus().getBody()));
        } catch (Exception e) {
            logger.error("Error sending initial status: {}", e.getMessage());
        }

        return emitter;
    }

    /**
     * GET /api/detection/stats — Aggregated detection statistics.
     * Used by the useDetectionStats frontend hook.
     */
    @GetMapping("/stats")
    public ResponseEntity<?> getDetectionStats() {
        LocalDateTime cutoff1hour = LocalDateTime.now().minusHours(1);
        String instituteId = getCurrentInstituteId();

        List<DetectionEvent> lastHour;
        if (instituteId != null) {
            lastHour = eventRepository.findByInstituteIdAndDetectedAtAfter(instituteId, cutoff1hour);
        } else {
            lastHour = eventRepository.findByDetectedAtAfter(cutoff1hour);
        }

        long criticalCount = lastHour.stream()
                .filter(e -> e.getSeverity() == DetectionEvent.Severity.CRITICAL).count();
        long highCount = lastHour.stream()
                .filter(e -> e.getSeverity() == DetectionEvent.Severity.HIGH).count();
        long mediumCount = lastHour.stream()
                .filter(e -> e.getSeverity() == DetectionEvent.Severity.MEDIUM).count();
        long lowCount = lastHour.stream()
                .filter(e -> e.getSeverity() == DetectionEvent.Severity.LOW).count();
        long attackEvents = criticalCount + highCount;

        LocalDateTime cutoff30sec = LocalDateTime.now().minusSeconds(30);
        List<DetectionEvent> last30sec;
        if (instituteId != null) {
            last30sec = eventRepository.findByInstituteIdAndDetectedAtAfter(instituteId, cutoff30sec);
        } else {
            last30sec = eventRepository.findByDetectedAtAfter(cutoff30sec);
        }
        int activeEvents = (int) last30sec.stream()
                .filter(e -> e.getSeverity() != DetectionEvent.Severity.LOW).count();

        boolean underAttack = last30sec.stream()
                .anyMatch(e -> e.getSeverity() == DetectionEvent.Severity.CRITICAL ||
                        e.getSeverity() == DetectionEvent.Severity.HIGH);

        // Fetch ML stats from ml-service (best effort)
        int mlModelsLoaded = 0;
        double avgConfidence = 0.0;
        double agreementRate = 0.0;
        try {
            @SuppressWarnings("unchecked")
            Map<String, Object> mlStats = new RestTemplate().getForObject(
                    "http://localhost:5000/model-stats", Map.class);
            if (mlStats != null) {
                mlModelsLoaded = mlStats.get("models_loaded") != null
                        ? ((Number) mlStats.get("models_loaded")).intValue()
                        : 0;
                avgConfidence = mlStats.get("average_confidence") != null
                        ? ((Number) mlStats.get("average_confidence")).doubleValue()
                        : 0.0;
                agreementRate = mlStats.get("model_agreement_rate") != null
                        ? ((Number) mlStats.get("model_agreement_rate")).doubleValue()
                        : 0.0;
            }
        } catch (Exception e) {
            logger.debug("ML service not reachable for stats: {}", e.getMessage());
        }

        Map<String, Object> result = new HashMap<>();
        result.put("total_packets", detectionService.getTotalPacketCount());
        result.put("total_events", lastHour.size());
        result.put("attack_events", attackEvents);
        result.put("critical_events", criticalCount);
        result.put("suspicious_events", mediumCount);
        result.put("current_status", underAttack ? "UNSAFE" : "SAFE");
        result.put("active_events", activeEvents);
        result.put("attacks_1hr", attackEvents + mediumCount);
        result.put("ml_models_loaded", mlModelsLoaded);
        result.put("avg_confidence", avgConfidence);
        result.put("agreement_rate", agreementRate);
        result.put("low_events", lowCount);

        return ResponseEntity.ok(result);
    }

    /**
     * POST /api/detection/inject-test-data — Insert synthetic events for
     * demo/testing.
     * Creates 20 events: 5 CRITICAL, 5 HIGH, 5 MEDIUM, 5 LOW.
     */
    @PostMapping("/inject-test-data")
    public ResponseEntity<?> injectTestData() {
        logger.info("Injecting 20 test detection events");

        String[] attackerMacs = {
                "AA:BB:CC:11:22:33", "AA:BB:CC:44:55:66", "AA:BB:CC:77:88:99",
                "AA:BB:CC:AA:BB:CC", "AA:BB:CC:DD:EE:FF"
        };
        String[] targetMacs = {
                "11:22:33:44:55:66", "22:33:44:55:66:77", "33:44:55:66:77:88",
                "44:55:66:77:88:99", "55:66:77:88:99:AA"
        };
        String[] bssids = {
                "00:11:22:33:44:55", "00:11:22:33:44:56", "00:11:22:33:44:57",
                "00:11:22:33:44:58", "00:11:22:33:44:59"
        };

        String instituteId = getCurrentInstituteId();
        int created = 0;

        // 5 CRITICAL events (score 75-95)
        for (int i = 0; i < 5; i++) {
            int score = 75 + (i * 5);
            DetectionEvent event = DetectionEvent.builder()
                    .attackerMac(attackerMacs[i])
                    .targetMac(targetMacs[i])
                    .targetBssid(bssids[i])
                    .instituteId(instituteId)
                    .layer1Score(score)
                    .layer2Score((int) (score * 0.9))
                    .layer3Score((int) (score * 0.5))
                    .totalScore(score)
                    .severity(DetectionEvent.Severity.CRITICAL)
                    .attackType(DetectionEvent.AttackType.DEAUTH_FLOOD)
                    .frameCount(50 + i * 20)
                    .attackDurationMs(5000 + i * 2000)
                    .mlPrediction("Attack")
                    .mlConfidence(0.85 + i * 0.03)
                    .modelAgreement("4/4")
                    .rateAnalyzerScore(30 + i)
                    .seqValidatorScore(20 + i)
                    .timeAnomalyScore(10 + i)
                    .sessionStateScore(15 + i)
                    .detectedAt(LocalDateTime.now().minusMinutes(i * 2))
                    .attackStart(LocalDateTime.now().minusMinutes(i * 2 + 1))
                    .build();
            eventRepository.save(event);
            created++;
        }

        // 5 HIGH events (score 30-48)
        for (int i = 0; i < 5; i++) {
            int score = 30 + (i * 4);
            DetectionEvent event = DetectionEvent.builder()
                    .attackerMac("DD:EE:FF:" + String.format("%02X:%02X:%02X", i + 1, i + 2, i + 3))
                    .targetMac(targetMacs[i])
                    .targetBssid(bssids[i % 3])
                    .instituteId(instituteId)
                    .layer1Score(score)
                    .layer2Score((int) (score * 0.8))
                    .layer3Score((int) (score * 0.3))
                    .totalScore(score)
                    .severity(DetectionEvent.Severity.HIGH)
                    .attackType(DetectionEvent.AttackType.TARGETED_DEAUTH)
                    .frameCount(15 + i * 5)
                    .attackDurationMs(2000 + i * 1000)
                    .mlPrediction("Attack")
                    .mlConfidence(0.65 + i * 0.04)
                    .modelAgreement("3/4")
                    .rateAnalyzerScore(15 + i * 2)
                    .seqValidatorScore(10 + i)
                    .timeAnomalyScore(5 + i)
                    .sessionStateScore(5 + i)
                    .detectedAt(LocalDateTime.now().minusMinutes(12 + i * 2))
                    .attackStart(LocalDateTime.now().minusMinutes(12 + i * 2 + 1))
                    .build();
            eventRepository.save(event);
            created++;
        }

        // 5 MEDIUM (suspicious) events (score 15-25)
        for (int i = 0; i < 5; i++) {
            int score = 15 + (i * 2);
            DetectionEvent event = DetectionEvent.builder()
                    .attackerMac("CC:DD:EE:" + String.format("%02X:%02X:%02X", i + 10, i + 11, i + 12))
                    .targetMac(targetMacs[i])
                    .targetBssid(bssids[i % 3])
                    .instituteId(instituteId)
                    .layer1Score(score)
                    .layer2Score(score / 2)
                    .layer3Score(0)
                    .totalScore(score)
                    .severity(DetectionEvent.Severity.MEDIUM)
                    .attackType(DetectionEvent.AttackType.UNKNOWN)
                    .frameCount(3 + i)
                    .attackDurationMs(500 + i * 200)
                    .mlPrediction("Normal")
                    .mlConfidence(0.45 + i * 0.03)
                    .modelAgreement("2/4")
                    .rateAnalyzerScore(5 + i)
                    .seqValidatorScore(3 + i)
                    .timeAnomalyScore(2 + i)
                    .sessionStateScore(2 + i)
                    .detectedAt(LocalDateTime.now().minusMinutes(25 + i * 2))
                    .attackStart(LocalDateTime.now().minusMinutes(25 + i * 2 + 1))
                    .build();
            eventRepository.save(event);
            created++;
        }

        // 5 LOW (normal disconnect) events (score 0-10)
        for (int i = 0; i < 5; i++) {
            int score = i * 2;
            DetectionEvent event = DetectionEvent.builder()
                    .attackerMac(targetMacs[i]) // Normal disconnects: "attacker" is the device itself
                    .targetMac(targetMacs[i])
                    .targetBssid(bssids[i % 3])
                    .instituteId(instituteId)
                    .layer1Score(score)
                    .layer2Score(0)
                    .layer3Score(0)
                    .totalScore(score)
                    .severity(DetectionEvent.Severity.LOW)
                    .attackType(DetectionEvent.AttackType.UNKNOWN)
                    .frameCount(1)
                    .attackDurationMs(0)
                    .mlPrediction("Normal")
                    .mlConfidence(0.10 + i * 0.02)
                    .modelAgreement("0/4")
                    .rateAnalyzerScore(0)
                    .seqValidatorScore(0)
                    .timeAnomalyScore(0)
                    .sessionStateScore(0)
                    .detectedAt(LocalDateTime.now().minusMinutes(35 + i * 3))
                    .attackStart(LocalDateTime.now().minusMinutes(35 + i * 3))
                    .build();
            eventRepository.save(event);
            created++;
        }

        logger.info("Injected {} test detection events", created);
        return ResponseEntity.ok(Map.of(
                "message", "Test data injected successfully",
                "events_created", created,
                "breakdown", Map.of("CRITICAL", 5, "HIGH", 5, "MEDIUM", 5, "LOW", 5)));
    }
}
