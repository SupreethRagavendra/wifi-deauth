package com.wifi.security.controller;

import com.wifi.security.dto.AttackAlertData;
import com.wifi.security.entity.User;
import com.wifi.security.repository.UserRepository;
import com.wifi.security.service.AlertNotificationService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * AlertController — Test endpoints for email/SMS alerts and alert log viewing.
 *
 * POST /api/alerts/test-email → Send test email to configured recipient
 * POST /api/alerts/test-sms → Send test SMS to configured number
 * GET /api/alerts/logs → View recent alert send logs
 */
@RestController
@RequestMapping("/api/alerts")
@CrossOrigin(origins = "*")
public class AlertController {

    private static final Logger logger = LoggerFactory.getLogger(AlertController.class);

    @Autowired
    private AlertNotificationService alertNotificationService;

    @Autowired
    private UserRepository userRepository;

    @Value("${alert.email.test-recipient:supreethvennnila@gmail.com}")
    private String testEmailRecipient;

    @Value("${alert.sms.test-number:+918667489900}")
    private String testSmsNumber;

    // In-memory alert log (last 100 entries)
    private static final CopyOnWriteArrayList<Map<String, Object>> alertLog = new CopyOnWriteArrayList<>();

    /**
     * POST /api/alerts/test-email
     * Sends a test email alert to the configured test recipient.
     */
    @PostMapping("/test-email")
    public ResponseEntity<?> sendTestEmail() {
        logger.info("📧 Sending test email to {}", testEmailRecipient);

        try {
            // Build test alert data
            AttackAlertData testData = AttackAlertData.builder()
                    .attackerMac("DE:AD:BE:EF:00:01")
                    .victimMac("CA:FE:BA:BE:00:02")
                    .confidence(87.5)
                    .ssid("TestNetwork-WiFiShield")
                    .timestamp(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))
                    .defenseLevel("HIGH")
                    .channel("6")
                    .status("TEST")
                    .build();

            // Create a temporary test user with the test email
            User testUser = new User();
            testUser.setName("Test Recipient");
            testUser.setEmail(testEmailRecipient);
            testUser.setAlertsEmail(true);

            alertNotificationService.sendEmailAlert(testUser, testData);

            logAlert("EMAIL", testEmailRecipient, true, null);
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Test email sent to " + testEmailRecipient,
                    "timestamp", Instant.now().toString()));

        } catch (Exception e) {
            logger.error("❌ Test email failed: {}", e.getMessage(), e);
            logAlert("EMAIL", testEmailRecipient, false, e.getMessage());
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Failed to send test email: " + e.getMessage()));
        }
    }

    /**
     * POST /api/alerts/test-sms
     * Sends a test SMS alert to the configured test number.
     */
    @PostMapping("/test-sms")
    public ResponseEntity<?> sendTestSms() {
        logger.info("📱 Sending test SMS to {}", testSmsNumber);

        try {
            AttackAlertData testData = AttackAlertData.builder()
                    .attackerMac("DE:AD:BE:EF:00:01")
                    .victimMac("CA:FE:BA:BE:00:02")
                    .confidence(87.5)
                    .ssid("TestNetwork-WiFiShield")
                    .timestamp(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")))
                    .defenseLevel("HIGH")
                    .channel("6")
                    .status("TEST")
                    .build();

            User testUser = new User();
            testUser.setName("Test Recipient");
            testUser.setPhoneNumber(testSmsNumber);
            testUser.setAlertsSms(true);

            alertNotificationService.sendSmsAlert(testUser, testData);

            logAlert("SMS", testSmsNumber, true, null);
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Test SMS sent to " + testSmsNumber,
                    "timestamp", Instant.now().toString()));

        } catch (Exception e) {
            logger.error("❌ Test SMS failed: {}", e.getMessage(), e);
            logAlert("SMS", testSmsNumber, false, e.getMessage());
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Failed to send test SMS: " + e.getMessage()));
        }
    }

    /**
     * GET /api/alerts/logs
     * View recent alert send history (last 100 entries).
     */
    @GetMapping("/logs")
    public ResponseEntity<?> getAlertLogs() {
        return ResponseEntity.ok(Map.of(
                "logs", alertLog,
                "total", alertLog.size()));
    }

    /**
     * Internal helper: log an alert send attempt.
     */
    private void logAlert(String type, String recipient, boolean success, String error) {
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("type", type);
        entry.put("recipient", recipient);
        entry.put("success", success);
        entry.put("timestamp", Instant.now().toString());
        if (error != null) {
            entry.put("error", error);
        }

        alertLog.add(entry);
        if (alertLog.size() > 100) {
            alertLog.subList(0, alertLog.size() - 100).clear();
        }
    }
}
