package com.wifi.security.service;

import com.wifi.security.dto.AttackAlertData;
import com.wifi.security.entity.User;
import com.wifi.security.enums.UserRole;
import com.wifi.security.repository.UserRepository;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * Service for sending attack alert notifications via Email (SMTP) and SMS
 * (smslocal.in).
 */
@Service
public class AlertNotificationService {

    private static final Logger logger = LoggerFactory.getLogger(AlertNotificationService.class);

    @Autowired
    private JavaMailSender mailSender;

    @Autowired
    private UserRepository userRepository;

    @Value("${alert.email.from:alerts@wifishield.io}")
    private String emailFrom;

    @Value("${alert.email.from-name:WiFi Shield Alerts}")
    private String emailFromName;

    @Value("${sms.api.key:}")
    private String smsApiKey;

    @Value("${sms.api.url:https://app.smslocal.in/api/smsapi}")
    private String smsApiUrl;

    @Value("${sms.api.sender:ALERTS}")
    private String smsSender;

    @Value("${sms.api.route:2}")
    private String smsRoute;

    @Value("${sms.api.templateid:}")
    private String smsTemplateId;

    private final HttpClient httpClient = HttpClient.newHttpClient();

    /**
     * Notify all relevant users (admin + affected viewers) about an attack.
     */
    @Async
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public void notifyAttack(String ssid, AttackAlertData alertData) {
        logger.info("Sending attack notifications for SSID/BSSID: {} | Confidence: {}%", ssid,
                alertData.getConfidence());

        try {
            // Find all users in the system (admins get all alerts)
            List<User> allUsers = userRepository.findAll();

            for (User user : allUsers) {
                boolean isAdmin = user.getRole() == UserRole.ADMIN;
                boolean isVictim = user.getMacAddress() != null &&
                        (user.getMacAddress().equalsIgnoreCase(alertData.getVictimMac()));

                // Viewer is affected if they monitor the attacked network BSSID
                boolean monitorsBssid = false;
                if (!isAdmin && user.getWifiMappings() != null) {
                    monitorsBssid = user.getWifiMappings().stream()
                            .anyMatch(mapping -> mapping.getWifiNetwork() != null
                                    && mapping.getWifiNetwork().getBssid() != null
                                    && mapping.getWifiNetwork().getBssid().equalsIgnoreCase(ssid));
                }

                if (!isAdmin && !isVictim && !monitorsBssid) {
                    continue;
                }

                // Send email (default to true if DB value is null)
                boolean sendEmail = user.getAlertsEmail() == null || user.getAlertsEmail();
                if (sendEmail && user.getEmail() != null) {
                    try {
                        sendEmailAlert(user, alertData);
                    } catch (Exception e) {
                        logger.error("Email alert failed for {}: {}", user.getEmail(), e.getMessage());
                    }
                }

                // Send SMS (default to true if DB value is null)
                boolean sendSms = user.getAlertsSms() == null || user.getAlertsSms();
                if (sendSms && user.getPhoneNumber() != null && !user.getPhoneNumber().isEmpty()) {
                    try {
                        sendSmsAlert(user, alertData);
                    } catch (Exception e) {
                        logger.error("SMS alert failed for {}: {}", user.getPhoneNumber(), e.getMessage());
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Failed to send attack notifications: {}", e.getMessage(), e);
        }
    }

    /**
     * Send an HTML email alert to a user.
     */
    public void sendEmailAlert(User user, AttackAlertData data) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        try {
            helper.setFrom(new jakarta.mail.internet.InternetAddress(emailFrom, emailFromName, "UTF-8"));
        } catch (java.io.UnsupportedEncodingException e) {
            helper.setFrom(emailFrom); // fallback
        }
        helper.setTo(user.getEmail());
        helper.setSubject("⚠️ WiFi Shield Alert: Deauthentication Attack Detected");

        String html = buildEmailHtml(user, data);
        helper.setText(html, true);

        mailSender.send(message);
        logger.info("✅ Email alert sent to: {}", user.getEmail());
    }

    /**
     * Send an SMS alert via smslocal.in API.
     */
    public void sendSmsAlert(User user, AttackAlertData data) {
        if (smsApiKey == null || smsApiKey.isEmpty()) {
            logger.warn("SMS API key not configured. Skipping SMS for {}", user.getPhoneNumber());
            return;
        }

        String smsText = String.format(
                "WiFi Shield Alert: Deauth attack detected! Attacker: %s, Confidence: %.1f%%, SSID: %s, Defense: %s. Check dashboard for details.",
                data.getAttackerMac(),
                data.getConfidence(),
                data.getSsid(),
                data.getDefenseLevel());

        try {
            String encodedSms = URLEncoder.encode(smsText, StandardCharsets.UTF_8);
            String encodedSender = URLEncoder.encode(smsSender, StandardCharsets.UTF_8);

            String queryParams = String.format(
                    "key=%s&campaign=0&routeid=%s&type=text&contacts=%s&senderid=%s&msg=%s",
                    smsApiKey, smsRoute, user.getPhoneNumber(), encodedSender, encodedSms);

            if (smsTemplateId != null && !smsTemplateId.isEmpty()) {
                queryParams += "&template_id=" + smsTemplateId;
            }

            HttpRequest request = HttpRequest.newBuilder()
                    .uri(URI.create(smsApiUrl + "?" + queryParams))
                    .GET()
                    .build();

            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
            logger.info("SMS sent to {} — status: {}, body: {}", user.getPhoneNumber(), response.statusCode(),
                    response.body());

        } catch (Exception e) {
            logger.error("SMS send failed for {}: {}", user.getPhoneNumber(), e.getMessage());
        }
    }

    /**
     * Build an HTML email body for the attack alert.
     */
    private String buildEmailHtml(User user, AttackAlertData data) {
        String severityColor = data.getConfidence() >= 85 ? "#dc2626"
                : data.getConfidence() >= 60 ? "#ea580c" : "#2563eb";

        return """
                <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #f8fafc;">
                    <div style="background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); padding: 24px; text-align: center;">
                        <h1 style="color: #ffffff; margin: 0; font-size: 22px;">🛡️ WiFi Shield</h1>
                        <p style="color: #94a3b8; margin: 4px 0 0 0; font-size: 13px;">Attack Alert Notification</p>
                    </div>
                    <div style="padding: 24px; background: #ffffff;">
                        <p style="color: #334155; font-size: 15px;">Hi <strong>%s</strong>,</p>
                        <p style="color: #334155; font-size: 14px;">A deauthentication attack has been detected on your network.</p>

                        <div style="background: #fef2f2; border-left: 4px solid %s; padding: 16px; border-radius: 6px; margin: 16px 0;">
                            <table style="width: 100%%; font-size: 13px; color: #334155;">
                                <tr><td style="padding: 4px 0; font-weight: 600;">Confidence:</td><td style="color: %s; font-weight: 700;">%.1f%%</td></tr>
                                <tr><td style="padding: 4px 0; font-weight: 600;">Attacker MAC:</td><td><code>%s</code></td></tr>
                                <tr><td style="padding: 4px 0; font-weight: 600;">Victim MAC:</td><td><code>%s</code></td></tr>
                                <tr><td style="padding: 4px 0; font-weight: 600;">SSID:</td><td>%s</td></tr>
                                <tr><td style="padding: 4px 0; font-weight: 600;">Channel:</td><td>%s</td></tr>
                                <tr><td style="padding: 4px 0; font-weight: 600;">Defense Level:</td><td>%s</td></tr>
                                <tr><td style="padding: 4px 0; font-weight: 600;">Time:</td><td>%s</td></tr>
                            </table>
                        </div>

                        <p style="color: #64748b; font-size: 13px;">
                            Automated defenses have been activated. Visit your <a href="http://localhost:3000/prevention" style="color: #2563eb;">Prevention Dashboard</a> for full details.
                        </p>
                    </div>
                    <div style="background: #f1f5f9; padding: 16px; text-align: center;">
                        <p style="color: #94a3b8; font-size: 11px; margin: 0;">WiFi Shield Security Platform • Automated Alert</p>
                    </div>
                </div>
                """
                .formatted(
                        user.getName(),
                        severityColor, severityColor,
                        data.getConfidence(),
                        data.getAttackerMac(),
                        data.getVictimMac(),
                        data.getSsid(),
                        data.getChannel() != null ? data.getChannel() : "N/A",
                        data.getDefenseLevel(),
                        data.getTimestamp());
    }
}
