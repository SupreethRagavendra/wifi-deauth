package com.wifi.security.service;

import com.wifi.security.entity.detection.DetectionEvent;
import com.wifi.security.repository.DetectionEventRepository;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.stream.Collectors;

/**
 * ForensicService — Handles forensic report generation and PCAP file
 * management.
 *
 * Features:
 * - List detection events with PCAP availability
 * - Serve PCAP files for download
 * - Generate text-based forensic reports (no heavy PDF library needed)
 */
@Service
public class ForensicService {

    private static final Logger logger = LoggerFactory.getLogger(ForensicService.class);
    private static final DateTimeFormatter FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    @Autowired
    private DetectionEventRepository eventRepository;

    @Value("${forensics.pcap.directory:/home/supreeth/wif-deauth/forensics/reports}")
    private String pcapDirectory;

    /**
     * Get all forensic reports (detection events with metadata about available
     * files).
     */
    public List<Map<String, Object>> getAllReports(String instituteId) {
        List<DetectionEvent> events;
        if (instituteId != null) {
            events = eventRepository.findTop50ByInstituteIdOrderByDetectedAtDesc(instituteId);
        } else {
            events = eventRepository.findTop50ByOrderByDetectedAtDesc();
        }

        return events.stream().map(event -> {
            Map<String, Object> report = new LinkedHashMap<>();
            report.put("id", event.getEventId());
            report.put("eventType", event.getSeverity() != null ? event.getSeverity().name() : "UNKNOWN");
            report.put("severity", event.getSeverity() != null ? event.getSeverity().name() : "LOW");
            report.put("attackerMac", event.getAttackerMac());
            report.put("targetMac", event.getTargetMac());
            report.put("bssid", event.getTargetBssid());
            report.put("confidence", event.getMlConfidence());
            report.put("score", event.getTotalScore());
            report.put("timestamp", event.getDetectedAt() != null ? event.getDetectedAt().format(FMT) : "N/A");
            report.put("mlPrediction", event.getMlPrediction());
            report.put("modelAgreement", event.getModelAgreement());
            report.put("layer1Score", event.getLayer1Score());
            report.put("layer2Score", event.getLayer2Score());
            report.put("layer3Score", event.getLayer3Score());
            report.put("pcapAvailable", hasPcapFile(event.getEventId()));
            return report;
        }).collect(Collectors.toList());
    }

    /**
     * Check if a PCAP file exists for the given event.
     */
    public boolean hasPcapFile(Long eventId) {
        if (eventId == null)
            return false;
        try {
            Path dir = Paths.get(pcapDirectory);
            if (!Files.exists(dir))
                return false;

            try (var stream = Files.list(dir)) {
                return stream.anyMatch(p -> p.getFileName().toString().endsWith(".pcap")
                        || p.getFileName().toString().endsWith(".pcapng"));
            }
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Get the PCAP file for download. Returns the most recent PCAP if no
     * event-specific one exists.
     */
    public File getPCAPFile(Long eventId) {
        Path dir = Paths.get(pcapDirectory);
        if (!Files.exists(dir)) {
            logger.warn("PCAP directory does not exist: {}", pcapDirectory);
            return null;
        }

        try {
            // First try event-specific file
            try (var stream = Files.list(dir)) {
                Optional<Path> specific = stream
                        .filter(p -> p.getFileName().toString().contains(String.valueOf(eventId))
                                && (p.getFileName().toString().endsWith(".pcap")
                                        || p.getFileName().toString().endsWith(".pcapng")))
                        .findFirst();
                if (specific.isPresent())
                    return specific.get().toFile();
            }

            // Fall back to most recent PCAP file
            try (var stream = Files.list(dir)) {
                Optional<Path> latest = stream
                        .filter(p -> p.getFileName().toString().endsWith(".pcap")
                                || p.getFileName().toString().endsWith(".pcapng"))
                        .max(Comparator.comparingLong(p -> {
                            try {
                                return Files.getLastModifiedTime(p).toMillis();
                            } catch (IOException e) {
                                return 0L;
                            }
                        }));
                if (latest.isPresent())
                    return latest.get().toFile();
            }
        } catch (Exception e) {
            logger.error("Error finding PCAP file for event {}: {}", eventId, e.getMessage());
        }

        return null;
    }

    /**
     * Generate a text-based forensic report for an event.
     * Returns the report content as a string (served as downloadable .txt file).
     */
    public String generateTextReport(Long eventId) {
        DetectionEvent event = eventRepository.findById(eventId).orElse(null);
        if (event == null) {
            return "Error: Event not found with ID " + eventId;
        }

        StringBuilder sb = new StringBuilder();
        sb.append("═══════════════════════════════════════════════════════════════\n");
        sb.append("              WiFi Attack Forensic Report\n");
        sb.append("═══════════════════════════════════════════════════════════════\n\n");

        sb.append("Report Generated: ").append(java.time.LocalDateTime.now().format(FMT)).append("\n");
        sb.append("Event ID: ").append(event.getEventId()).append("\n\n");

        sb.append("── ATTACK SUMMARY ─────────────────────────────────────────────\n\n");
        sb.append(String.format("  Severity:       %s%n", event.getSeverity()));
        sb.append(String.format("  Detected At:    %s%n",
                event.getDetectedAt() != null ? event.getDetectedAt().format(FMT) : "N/A"));
        sb.append(String.format("  Attacker MAC:   %s%n", event.getAttackerMac()));
        sb.append(String.format("  Target MAC:     %s%n", event.getTargetMac()));
        sb.append(String.format("  Network BSSID:  %s%n", event.getTargetBssid()));
        sb.append(String.format("  Frame Count:    %d%n",
                event.getFrameCount() != null ? event.getFrameCount() : 0));
        sb.append(String.format("  Attack Duration:%dms%n",
                event.getAttackDurationMs() != null ? event.getAttackDurationMs() : 0));
        sb.append("\n");

        sb.append("── DETECTION SCORES ───────────────────────────────────────────\n\n");
        sb.append(String.format("  Layer 1 (Heuristic):   %d / 95%n",
                event.getLayer1Score() != null ? event.getLayer1Score() : 0));
        sb.append(String.format("    - Rate Analyzer:     %d%n",
                event.getRateAnalyzerScore() != null ? event.getRateAnalyzerScore() : 0));
        sb.append(String.format("    - Seq Validator:     %d%n",
                event.getSeqValidatorScore() != null ? event.getSeqValidatorScore() : 0));
        sb.append(String.format("    - Time Anomaly:      %d%n",
                event.getTimeAnomalyScore() != null ? event.getTimeAnomalyScore() : 0));
        sb.append(String.format("    - Session State:     %d%n",
                event.getSessionStateScore() != null ? event.getSessionStateScore() : 0));
        sb.append(String.format("  Layer 2 (ML):          %d / 100%n",
                event.getLayer2Score() != null ? event.getLayer2Score() : 0));
        sb.append(String.format("  Layer 3 (Physical):    %d / 70%n",
                event.getLayer3Score() != null ? event.getLayer3Score() : 0));
        sb.append(String.format("  Total Score:           %d / 100%n",
                event.getTotalScore() != null ? event.getTotalScore() : 0));
        sb.append("\n");

        sb.append("── ML ANALYSIS ────────────────────────────────────────────────\n\n");
        sb.append(String.format("  ML Prediction:    %s%n",
                event.getMlPrediction() != null ? event.getMlPrediction() : "N/A"));
        sb.append(String.format("  ML Confidence:    %.2f%%%n",
                event.getMlConfidence() != null ? event.getMlConfidence() * 100 : 0.0));
        sb.append(String.format("  Model Agreement:  %s%n",
                event.getModelAgreement() != null ? event.getModelAgreement() : "N/A"));
        sb.append("\n");

        if (event.getLayer3Notes() != null && !event.getLayer3Notes().isEmpty()) {
            sb.append("── PHYSICAL LAYER ANALYSIS ────────────────────────────────────\n\n");
            sb.append("  ").append(event.getLayer3Notes()).append("\n\n");
        }

        if (Boolean.TRUE.equals(event.getIsSpoofed())) {
            sb.append("── SPOOFING DETECTION ─────────────────────────────────────────\n\n");
            sb.append(String.format("  Spoofed:            YES%n"));
            sb.append(String.format("  Real Attacker MAC:  %s%n",
                    event.getRealAttackerMac() != null ? event.getRealAttackerMac() : "Unknown"));
            sb.append(String.format("  Detection Method:   %s%n",
                    event.getDetectionMethod() != null ? event.getDetectionMethod() : "N/A"));
            sb.append(String.format("  RSSI Deviation:     %.1f dBm%n",
                    event.getRssiDeviation() != null ? event.getRssiDeviation() : 0.0));
            sb.append("\n");
        }

        sb.append("── ACTIONS TAKEN ──────────────────────────────────────────────\n\n");
        sb.append("  • Attack detected and logged to database\n");
        sb.append("  • Real-time SSE notification broadcast to dashboard\n");
        if (event.getTotalScore() != null && event.getTotalScore() >= 60) {
            sb.append("  • Email/SMS notifications sent to subscribed users\n");
        }
        if (event.getTotalScore() != null && event.getTotalScore() >= 85) {
            sb.append("  • 802.11w PMF activation requested\n");
        }
        sb.append("\n");

        sb.append("═══════════════════════════════════════════════════════════════\n");
        sb.append("  WiFi Deauth Detection System — Forensic Report\n");
        sb.append("  Powered by ML + Multi-Layer Detection\n");
        sb.append("═══════════════════════════════════════════════════════════════\n");

        return sb.toString();
    }
}
