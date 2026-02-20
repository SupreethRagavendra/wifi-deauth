package com.wifi.security.service;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.wifi.security.dto.response.WiFiScanResult;
import com.wifi.security.dto.response.ConnectedClientResponse;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class WiFiScannerService {

    private static final Logger log = LoggerFactory.getLogger(WiFiScannerService.class);
    private final ObjectMapper objectMapper;

    // Path to the python script
    private static final String SCRIPT_PATH = "/home/supreeth/wif-deauth/packet-capture/scan_networks.py";
    private static final String CLIENT_SCRIPT_PATH = "/home/supreeth/wif-deauth/packet-capture/scan_clients.py";

    @org.springframework.beans.factory.annotation.Value("${detection.monitor.interface:wlan0mon}")
    private String monitorInterface;

    private final com.wifi.security.repository.ScanResultRepository scanResultRepository;
    private final com.wifi.security.repository.DetectedAnomalyRepository anomalyRepository;
    private final com.wifi.security.repository.WiFiNetworkRepository wifiNetworkRepository;

    public List<WiFiScanResult> scanNetworks(com.wifi.security.entity.Institute institute) {
        log.info("Starting WiFi scan using python script: {}", SCRIPT_PATH);
        List<WiFiScanResult> results = new ArrayList<>();

        try {
            // Command: python3 scan_networks.py --interface <interface>
            ProcessBuilder pb = new ProcessBuilder("python3", SCRIPT_PATH, "--interface", monitorInterface);
            pb.redirectErrorStream(false);

            Process process = pb.start();

            // Read output
            StringBuilder jsonOutput = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    jsonOutput.append(line);
                }
            }

            // Read errors logs
            try (BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = errorReader.readLine()) != null) {
                    log.debug("Python Scan Log: {}", line);
                }
            }

            boolean finished = process.waitFor(15, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                log.error("Scan timed out");
                return results;
            }

            if (process.exitValue() != 0) {
                log.error("Scan script failed with exit code: {}", process.exitValue());
                return results;
            }

            String jsonString = jsonOutput.toString().trim();
            if (jsonString.startsWith("[")) {
                results = objectMapper.readValue(jsonString, new TypeReference<List<WiFiScanResult>>() {
                });
                log.info("Scan complete. Found {} networks.", results.size());

                // Save results to DB if institute provided (means triggered by registered
                // user/admin)
                if (institute != null) {
                    saveScanResults(results, institute);
                }

            } else {
                log.warn("Invalid JSON output from scan script: {}", jsonString);
            }

        } catch (Exception e) {
            log.error("Error executing scan script", e);
        }

        return results;
    }

    public List<ConnectedClientResponse> scanClients(String bssid, Integer channel) {
        log.info("Starting Client scan for BSSID: {} on Channel: {} using python script: {}", bssid, channel,
                CLIENT_SCRIPT_PATH);
        List<ConnectedClientResponse> results = new ArrayList<>();

        if (bssid == null || bssid.isEmpty()) {
            return results;
        }

        try {
            // Command: python3 scan_clients.py --bssid <BSSID> [--channel <CH>]
            List<String> command = new ArrayList<>();
            command.add("python3");
            command.add(CLIENT_SCRIPT_PATH);
            command.add("--bssid");
            command.add(bssid);

            // Pass configured monitor interface
            command.add("--interface");
            command.add(monitorInterface);

            if (channel != null) {
                command.add("--channel");
                command.add(String.valueOf(channel));
            }

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(false);

            Process process = pb.start();

            // Read output
            StringBuilder jsonOutput = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    jsonOutput.append(line);
                }
            }

            // Read errors logs
            try (BufferedReader errorReader = new BufferedReader(new InputStreamReader(process.getErrorStream()))) {
                String line;
                while ((line = errorReader.readLine()) != null) {
                    log.debug("Python Client Scan Log: {}", line);
                }
            }

            boolean finished = process.waitFor(25, TimeUnit.SECONDS);
            if (!finished) {
                process.destroyForcibly();
                log.error("Client Scan timed out");
                return results;
            }

            if (process.exitValue() != 0) {
                log.error("Client Scan script failed with exit code: {}", process.exitValue());
                return results;
            }

            String jsonString = jsonOutput.toString().trim();
            if (jsonString.startsWith("[")) {
                results = objectMapper.readValue(jsonString, new TypeReference<List<ConnectedClientResponse>>() {
                });
                log.info("Client Scan complete for {}. Found {} clients.", bssid, results.size());
            } else {
                log.warn("Invalid JSON output from client scan script: {}", jsonString);
            }

        } catch (Exception e) {
            log.error("Error executing client scan script", e);
        }

        if (results.isEmpty()) {
            log.info("No real clients found via script.");
        }

        return results;
    }

    // Default method for backward compatibility
    public List<WiFiScanResult> scanNetworks() {
        return scanNetworks(null);
    }

    @org.springframework.transaction.annotation.Transactional
    protected void saveScanResults(List<WiFiScanResult> scanResults, com.wifi.security.entity.Institute institute) {
        List<com.wifi.security.entity.ScanResult> entities = new ArrayList<>();

        for (WiFiScanResult res : scanResults) {
            com.wifi.security.entity.ScanResult entity = com.wifi.security.entity.ScanResult.builder()
                    .scanId(java.util.UUID.randomUUID().toString())
                    .institute(institute)
                    .ssid(res.getSsid())
                    .bssid(res.getBssid())
                    .channel(res.getChannel())
                    // .frequencyBand(res.getFrequencyBand()) // Add if DTO has it
                    .rssi(res.getRssi())
                    .estimatedDistance(res.getEstimatedDistance())
                    .security(res.getSecurity())
                    .build();
            entities.add(entity);
        }

        scanResultRepository.saveAll(entities);
        detectAnomalies(entities, institute);
    }

    private void detectAnomalies(List<com.wifi.security.entity.ScanResult> currentScan,
            com.wifi.security.entity.Institute institute) {
        // Logic to compare with configured networks
        List<com.wifi.security.entity.WiFiNetwork> registeredParams = wifiNetworkRepository.findByInstitute(institute);

        // Check 1: Missing Networks (Critical)
        for (com.wifi.security.entity.WiFiNetwork registered : registeredParams) {
            boolean found = currentScan.stream().anyMatch(s -> s.getBssid().equalsIgnoreCase(registered.getBssid()));
            if (!found) {
                // Raise anomaly
                com.wifi.security.entity.DetectedAnomaly anomaly = com.wifi.security.entity.DetectedAnomaly.builder()
                        .anomalyId(java.util.UUID.randomUUID().toString())
                        .institute(institute)
                        .anomalyType(com.wifi.security.entity.DetectedAnomaly.AnomalyType.MISSING_NETWORK)
                        .description("Registered network " + registered.getSsid() + " is missing from scan.")
                        .severity(com.wifi.security.entity.DetectedAnomaly.Severity.CRITICAL)
                        .build();
                anomalyRepository.save(anomaly);
            }
        }

        // Check 2: Security Mismatch
        for (com.wifi.security.entity.WiFiNetwork registered : registeredParams) {
            currentScan.stream()
                    .filter(s -> s.getBssid().equalsIgnoreCase(registered.getBssid()))
                    .findFirst()
                    .ifPresent(scanned -> {
                        // Normalize security comparision
                        String scannedSec = scanned.getSecurity();
                        String regSec = registered.getSecurityType().name(); // WPA2, WPA3

                        // Simple check: if registered is WPA2 but scanned is OPEN -> Critical
                        if (!scannedSec.contains(regSec) && !scannedSec.equals("WPA2_ENTERPRISE")) { // Lazy check
                            if (scannedSec.equals("OPEN")) {
                                com.wifi.security.entity.DetectedAnomaly anomaly = com.wifi.security.entity.DetectedAnomaly
                                        .builder()
                                        .anomalyId(java.util.UUID.randomUUID().toString())
                                        .institute(institute)
                                        .anomalyType(
                                                com.wifi.security.entity.DetectedAnomaly.AnomalyType.SECURITY_MISMATCH)
                                        .description("Network " + registered.getSsid()
                                                + " is broadcasting as OPEN but registered as " + regSec)
                                        .severity(com.wifi.security.entity.DetectedAnomaly.Severity.CRITICAL)
                                        .build();
                                anomalyRepository.save(anomaly);
                            }
                        }
                    });
        }
    }
}
