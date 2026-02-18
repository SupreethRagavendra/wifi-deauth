package com.wifi.security.controller;

import com.wifi.security.dto.response.WiFiScanResult;
import com.wifi.security.entity.Institute;
import com.wifi.security.entity.User;
import com.wifi.security.exception.ResourceNotFoundException;
import com.wifi.security.repository.UserRepository;
import com.wifi.security.service.WiFiScannerService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/scan")
@RequiredArgsConstructor
public class ScanController {

    private final WiFiScannerService wiFiScannerService;
    private final UserRepository userRepository;
    private final com.wifi.security.repository.ScanResultRepository scanResultRepository;
    private final com.wifi.security.repository.DetectedAnomalyRepository anomalyRepository;

    @PostMapping("/trigger")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<WiFiScanResult>> triggerManualScan() {
        User user = getCurrentUser();
        Institute institute = user.getInstitute();

        // This will now save results and detect anomalies
        List<WiFiScanResult> results = wiFiScannerService.scanNetworks(institute);
        return ResponseEntity.ok(results);
    }

    @GetMapping("/latest")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<com.wifi.security.entity.ScanResult>> getLatestScanResults() {
        User user = getCurrentUser();
        return ResponseEntity.ok(scanResultRepository.findByInstituteOrderByScannedAtDesc(user.getInstitute()));
    }

    @GetMapping("/alerts")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<com.wifi.security.entity.DetectedAnomaly>> getDetectedAnomalies() {
        User user = getCurrentUser();
        return ResponseEntity.ok(anomalyRepository.findByInstituteOrderByDetectedAtDesc(user.getInstitute()));
    }

    // Additional endpoints could be added here for /latest and /alerts

    private User getCurrentUser() {
        String email = SecurityContextHolder.getContext().getAuthentication().getName();
        return userRepository.findByEmailWithInstitute(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", email));
    }
}
