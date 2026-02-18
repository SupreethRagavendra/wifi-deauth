package com.wifi.security.controller;

import com.wifi.security.dto.AlertDTO;
import com.wifi.security.service.DetectionService;
import com.wifi.security.service.AlertService;
import com.wifi.security.service.layer1.Layer1Service;
import com.wifi.security.entity.detection.DetectionEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

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

    @PostMapping("/alert")
    public ResponseEntity<?> receiveAlert(@RequestBody AlertDTO alert) {
        logger.warn("🚨 ALERT RECEIVED: type={} severity={} attacker={}",
                alert.getType(), alert.getSeverity(), alert.getAttackerMac());

        alertService.processAlert(alert);

        return ResponseEntity.ok(Map.of(
                "status", "alert_processed",
                "type", alert.getType()));
    }

    @GetMapping("/status")
    public ResponseEntity<?> getDetectionStatus() {
        return ResponseEntity.ok(detectionService.getCurrentStatus());
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
            if (events != null && !events.isEmpty()) {
                logger.info("Returning {} detection events from database", events.size());
                return ResponseEntity.ok(events);
            }
            logger.warn("Database detection events empty, checking in-memory alerts fallback");
        } catch (Exception e) {
            logger.error("Error fetching detection events: {}", e.getMessage());
        }

        // Fallback to alerts if database query fails or is empty
        List<AlertDTO> alerts = alertService.getRecentAlerts();
        List<Map<String, Object>> events = new ArrayList<>();

        for (AlertDTO alert : alerts) {
            Map<String, Object> event = new HashMap<>();
            event.put("eventId", eventIdCounter.getAndIncrement()); // Generate temporary ID
            event.put("attackerMac", alert.getAttackerMac() != null ? alert.getAttackerMac() : "unknown");
            event.put("targetBssid", alert.getTargetBssid() != null ? alert.getTargetBssid() : "unknown");
            event.put("layer1Score", calculateScore(alert));
            event.put("totalScore", calculateScore(alert));
            event.put("severity", mapSeverity(alert.getSeverity()));
            event.put("detectedAt", alert.getTimestamp() != null ? alert.getTimestamp() : Instant.now().toString());
            event.put("attackType", alert.getType()); // Mapped to attackType enum string
            event.put("message", alert.getMessage());
            event.put("channel", alert.getChannel());
            event.put("signal", alert.getSignal());
            event.put("frameCount", alert.getPacketCount()); // Map packetCount to frameCount
            // Add defaults for missing fields
            event.put("confidence", 1.0);
            event.put("layer2Score", 0);
            event.put("layer3Score", 0);
            event.put("alertSent", true);

            events.add(event);
        }

        logger.info("Returning {} events from in-memory alerts fallback", events.size());
        Collections.reverse(events);
        return ResponseEntity.ok(events);
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
                    .data(detectionService.getCurrentStatus()));
        } catch (Exception e) {
            logger.error("Error sending initial status: {}", e.getMessage());
        }

        return emitter;
    }
}
