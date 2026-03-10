package com.wifi.security.controller;

import com.wifi.security.entity.User;
import com.wifi.security.enums.UserRole;
import com.wifi.security.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/system")
@CrossOrigin(origins = "*")
public class SystemSettingsController {

    private static final org.slf4j.Logger logger = org.slf4j.LoggerFactory.getLogger(SystemSettingsController.class);

    @Autowired
    private UserRepository userRepository;

    /**
     * Get the active system WiFi adapter.
     * Looks for the first ADMIN user's configured adapter (since the sniffer runs
     * system-wide).
     * Falls back to "wlan1" if no admin is found.
     * 
     * GET /api/system/adapter
     */
    @GetMapping("/adapter")
    public ResponseEntity<Map<String, String>> getSystemAdapter() {
        List<User> admins = userRepository.findAll().stream()
                .filter(u -> u.getRole() == UserRole.ADMIN)
                .collect(java.util.stream.Collectors.toList());
        String adapter = "wlan1"; // Default

        if (!admins.isEmpty()) {
            User firstAdmin = admins.get(0);
            if (firstAdmin.getWifiAdapter() != null && !firstAdmin.getWifiAdapter().isEmpty()) {
                adapter = firstAdmin.getWifiAdapter();
            }
        }

        return ResponseEntity.ok(Map.of("adapter", adapter));
    }

    /**
     * GET /api/system/adapters
     * Detect all available wireless interfaces with their status.
     */
    @GetMapping("/adapters")
    public ResponseEntity<?> listAdapters() {
        logger.info("Detecting wireless adapters...");
        List<Map<String, Object>> adapters = new java.util.ArrayList<>();

        try {
            // Use 'iw dev' to list wireless interfaces
            ProcessBuilder pb = new ProcessBuilder("iw", "dev");
            pb.redirectErrorStream(true);
            Process proc = pb.start();

            String output;
            try (java.io.BufferedReader reader = new java.io.BufferedReader(
                    new java.io.InputStreamReader(proc.getInputStream()))) {
                output = reader.lines().collect(java.util.stream.Collectors.joining("\n"));
            }
            proc.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);

            // Parse 'iw dev' output
            String currentIface = null;
            Map<String, Object> current = null;

            for (String line : output.split("\n")) {
                line = line.trim();
                if (line.startsWith("Interface ")) {
                    if (current != null)
                        adapters.add(current);
                    currentIface = line.substring("Interface ".length()).trim();
                    current = new java.util.LinkedHashMap<>();
                    current.put("name", currentIface);
                    current.put("status", "UP");
                } else if (current != null) {
                    if (line.startsWith("type ")) {
                        String type = line.substring(5).trim();
                        current.put("mode", type);
                        current.put("monitorMode", "monitor".equalsIgnoreCase(type));
                    } else if (line.startsWith("channel ")) {
                        current.put("channel", line.substring(8).trim());
                    } else if (line.startsWith("addr ")) {
                        current.put("mac", line.substring(5).trim());
                    }
                }
            }
            if (current != null)
                adapters.add(current);

            // Also try /sys/class/net for interfaces not shown by iw
            try {
                java.io.File netDir = new java.io.File("/sys/class/net");
                if (netDir.exists()) {
                    for (java.io.File iface : netDir.listFiles()) {
                        if (new java.io.File(iface, "wireless").exists() ||
                                new java.io.File(iface, "phy80211").exists()) {
                            String name = iface.getName();
                            boolean alreadyListed = adapters.stream()
                                    .anyMatch(a -> name.equals(a.get("name")));
                            if (!alreadyListed) {
                                Map<String, Object> sysAdapter = new java.util.LinkedHashMap<>();
                                sysAdapter.put("name", name);
                                sysAdapter.put("status", "DOWN");
                                sysAdapter.put("monitorMode", false);
                                adapters.add(sysAdapter);
                            }
                        }
                    }
                }
            } catch (Exception e) {
                // Non-critical
            }

        } catch (Exception e) {
            logger.error("Failed to detect adapters: {}", e.getMessage());
            return ResponseEntity.ok(Map.of(
                    "adapters", adapters,
                    "error", "Could not run 'iw dev': " + e.getMessage()));
        }

        return ResponseEntity.ok(Map.of(
                "adapters", adapters,
                "count", adapters.size()));
    }
}
