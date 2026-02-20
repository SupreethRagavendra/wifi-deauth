package com.wifi.security.controller;

import com.wifi.security.dto.AlertDTO;
import com.wifi.security.service.DetectionService;
import com.wifi.security.service.AlertService;
import com.wifi.security.service.layer1.Layer1Service;
import com.wifi.security.entity.detection.DetectionEvent;
import com.wifi.security.repository.DetectionEventRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.time.LocalDateTime;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicLong;

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

    @PostMapping("/alert")
    public ResponseEntity<?> receiveAlert(@RequestBody AlertDTO alert) {
        logger.warn("🚨 ALERT RECEIVED: type={} severity={} attacker={}",
                alert.getType(), alert.getSeverity(), alert.getAttackerMac());

        alertService.processAlert(alert);

        return ResponseEntity.ok(Map.of(
                "status", "alert_processed",
                "type", alert.getType()));
    }

    @GetMapping("/live-status")
    public ResponseEntity<?> getLiveStatus() {
        LocalDateTime cutoff15sec = LocalDateTime.now().minusSeconds(15);
        LocalDateTime cutoff1hour = LocalDateTime.now().minusHours(1);

        List<DetectionEvent> last15sec = eventRepository.findByDetectedAtAfter(cutoff15sec);
        List<DetectionEvent> lastHour = eventRepository.findByDetectedAtAfter(cutoff1hour);

        boolean underAttack = last15sec.stream()
                .anyMatch(e -> e.getSeverity().name()
                        .equals("CRITICAL") ||
                        e.getSeverity().name().equals("HIGH"));

        int activeThreats = (int) last15sec.stream()
                .filter(e -> e.getSeverity().name()
                        .equals("CRITICAL") ||
                        e.getSeverity().name().equals("HIGH"))
                .count();

        return ResponseEntity.ok(Map.of(
                "systemStatus", underAttack ? "UNSAFE" : "SAFE",
                "activeThreats", activeThreats,
                "threatsLastHour", (int) lastHour.stream()
                        .filter(e -> e.getSeverity().name().equals("CRITICAL") || e.getSeverity().name().equals("HIGH"))
                        .count(),
                "underAttack", underAttack,
                "timestamp", LocalDateTime.now().toString()));
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
        return ResponseEntity.ok(Map.of("message", "All detection events cleared"));
    }

    /**
     * Endpoint for frontend: GET /api/detection/events/recent
     * Returns actual DetectionEvent entities from database
     */
    @GetMapping("/events/recent")
    public ResponseEntity<?> getRecentDetectionEvents() {
        logger.debug("Frontend requesting recent detection events");

        try {
            List<DetectionEvent> events = layer1Service.getRecentEvents();
            logger.info("Returning {} detection events from database", events.size());
            return ResponseEntity.ok(events != null ? events : List.of());
        } catch (Exception e) {
            logger.error("Error fetching events: {}", e.getMessage());
            return ResponseEntity.ok(List.of());
        }
    }

    private int calculateScore(AlertDTO alert) {
        // Calculate a threat score (0-100) based on alert data
        int score = 0;

        // Base score from severity
        if ("CRITICAL".equals(alert.getSeverity()))
            score = 85;
        else if ("HIGH".equals(alert.getSeverity()))
            score = 70;
        else if ("MEDIUM".equals(alert.getSeverity()))
            score = 40;
        else
            score = 15;

        // Bonus for packet count
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
