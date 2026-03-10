package com.wifi.security.controller;

import com.wifi.security.repository.UserRepository;
import com.wifi.security.service.ForensicService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * ForensicController — Endpoints for forensic evidence retrieval.
 *
 * GET /api/forensics/reports → List all forensic reports
 * GET /api/forensics/reports/{id}/pcap → Download PCAP file for an event
 * GET /api/forensics/reports/{id}/pdf → Download text forensic report
 */
@RestController
@RequestMapping("/api/forensics")
@CrossOrigin(origins = "*")
public class ForensicController {

    private static final Logger logger = LoggerFactory.getLogger(ForensicController.class);

    @Autowired
    private ForensicService forensicService;

    @Autowired
    private UserRepository userRepository;

    /**
     * GET /api/forensics/reports
     * Returns list of detection events with forensic data and PCAP availability.
     */
    @GetMapping("/reports")
    public ResponseEntity<?> getAllReports() {
        String instituteId = getCurrentInstituteId();
        List<Map<String, Object>> reports = forensicService.getAllReports(instituteId);
        return ResponseEntity.ok(reports);
    }

    /**
     * GET /api/forensics/reports/{id}/pcap
     * Download the PCAP file associated with a detection event.
     */
    @GetMapping("/reports/{id}/pcap")
    public ResponseEntity<Resource> downloadPCAP(@PathVariable Long id) {
        logger.info("PCAP download requested for event {}", id);

        File pcapFile = forensicService.getPCAPFile(id);
        if (pcapFile == null || !pcapFile.exists()) {
            logger.warn("No PCAP file found for event {}", id);
            return ResponseEntity.notFound().build();
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"forensic_" + id + "_" + pcapFile.getName() + "\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .contentLength(pcapFile.length())
                .body(new FileSystemResource(pcapFile));
    }

    /**
     * GET /api/forensics/reports/{id}/pdf
     * Generate and download a text-based forensic report.
     * (Named /pdf for API compatibility but returns a comprehensive text report)
     */
    @GetMapping("/reports/{id}/pdf")
    public ResponseEntity<byte[]> downloadReport(@PathVariable Long id) {
        logger.info("Forensic report requested for event {}", id);

        String report = forensicService.generateTextReport(id);
        byte[] content = report.getBytes(StandardCharsets.UTF_8);

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION,
                        "attachment; filename=\"forensic_report_" + id + ".txt\"")
                .contentType(MediaType.TEXT_PLAIN)
                .contentLength(content.length)
                .body(content);
    }

    // Helper: extract institute ID from JWT context
    private String getCurrentInstituteId() {
        try {
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            if (auth != null && auth.getName() != null) {
                return userRepository.findByEmail(auth.getName())
                        .map(u -> u.getInstitute() != null ? u.getInstitute().getInstituteId() : null)
                        .orElse(null);
            }
        } catch (Exception e) {
            logger.warn("Could not extract instituteId: {}", e.getMessage());
        }
        return null;
    }
}
