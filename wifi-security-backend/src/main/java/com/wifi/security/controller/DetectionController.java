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
}
