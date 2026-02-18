package com.wifi.security.controller;

import com.wifi.security.entity.Institute;
import com.wifi.security.entity.User;
import com.wifi.security.entity.UserWiFiMapping;
import com.wifi.security.entity.WiFiNetwork;
import com.wifi.security.enums.SecurityType;
import com.wifi.security.enums.UserRole;
import com.wifi.security.exception.ResourceNotFoundException;
import com.wifi.security.exception.UnauthorizedException;
import com.wifi.security.repository.UserRepository;
import com.wifi.security.repository.UserWiFiMappingRepository;
import com.wifi.security.repository.WiFiNetworkRepository;
import com.wifi.security.service.WiFiScannerService;
import com.wifi.security.dto.response.ConnectedClientResponse;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

/**
 * Controller for WiFi network endpoints.
 */
@RestController
@RequestMapping("/api/wifi")
@CrossOrigin(origins = { "http://localhost:3000", "http://localhost:5173" })
@Transactional(readOnly = true)
public class WiFiController {

    private static final Logger logger = LoggerFactory.getLogger(WiFiController.class);

    private final WiFiNetworkRepository wifiNetworkRepository;
    private final UserRepository userRepository;
    private final UserWiFiMappingRepository userWiFiMappingRepository;

    private final WiFiScannerService wifiScannerService;

    public WiFiController(WiFiNetworkRepository wifiNetworkRepository,
            UserRepository userRepository,
            UserWiFiMappingRepository userWiFiMappingRepository,
            WiFiScannerService wifiScannerService) {
        this.wifiNetworkRepository = wifiNetworkRepository;
        this.userRepository = userRepository;
        this.userWiFiMappingRepository = userWiFiMappingRepository;
        this.wifiScannerService = wifiScannerService;
    }

    /**
     * Scan for nearby WiFi networks (ADMIN only).
     * 
     * GET /api/wifi/scan
     */
    @GetMapping("/scan")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<com.wifi.security.dto.response.WiFiScanResult>> scanNearbyNetworks() {
        User user = getCurrentUser();
        return ResponseEntity.ok(wifiScannerService.scanNetworks(user.getInstitute()));
    }

    // DTO for WiFi network requests
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class WiFiNetworkRequest {
        @NotBlank(message = "SSID is required")
        private String ssid;

        @NotBlank(message = "BSSID is required")
        @Pattern(regexp = "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", message = "Invalid MAC address format")
        private String bssid;

        private Integer channel;
        private SecurityType securityType;
        private String location;
    }

    // DTO for WiFi network response
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    @Builder
    public static class WiFiNetworkResponse {
        private String wifiId;
        private String ssid;
        private String bssid;
        private Integer channel;
        private String securityType;
        private String location;
        private String createdByUserId;
        private String createdByUserName;
        private LocalDateTime createdAt;
    }

    // DTO for assigning WiFi to viewer
    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class AssignWiFiRequest {
        @NotBlank(message = "Viewer ID is required")
        private String viewerId;

        @NotBlank(message = "WiFi ID is required")
        private String wifiId;
    }

    /**
     * Create a new WiFi network (ADMIN only).
     * 
     * POST /api/wifi
     */
    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<WiFiNetworkResponse> createWiFiNetwork(
            @Valid @RequestBody WiFiNetworkRequest request) {
        User user = getCurrentUser();
        Institute institute = user.getInstitute();

        if (institute == null) {
            throw new UnauthorizedException("User does not belong to an institute");
        }

        logger.info("Creating WiFi network: {} for institute: {}",
                request.getSsid(), institute.getInstituteName());

        WiFiNetwork network = WiFiNetwork.builder()
                .wifiId(UUID.randomUUID().toString())
                .institute(institute)
                .ssid(request.getSsid().trim())
                .bssid(request.getBssid().toUpperCase())
                .channel(request.getChannel())
                .securityType(request.getSecurityType() != null ? request.getSecurityType() : SecurityType.WPA2)
                .location(request.getLocation())
                .createdByUser(user)
                .build();

        network = wifiNetworkRepository.save(network);

        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(network));
    }

    /**
     * Get WiFi networks.
     * ADMIN: All networks for their institute
     * VIEWER: Only assigned networks
     * 
     * GET /api/wifi
     */
    @GetMapping
    @PreAuthorize("isAuthenticated()")
    public ResponseEntity<List<WiFiNetworkResponse>> getWiFiNetworks() {
        User user = getCurrentUser();
        Institute institute = user.getInstitute();

        List<WiFiNetwork> networks;

        if (user.getRole() == UserRole.ADMIN) {
            // Admin sees all networks for their institute
            networks = wifiNetworkRepository.findByInstituteWithCreator(institute);
            logger.debug("Admin {} fetching {} networks", user.getEmail(), networks.size());
        } else {
            // Viewer sees only assigned networks
            List<UserWiFiMapping> mappings = userWiFiMappingRepository.findByUser(user);
            networks = mappings.stream()
                    .map(UserWiFiMapping::getWifiNetwork)
                    .collect(Collectors.toList());
            logger.debug("Viewer {} fetching {} assigned networks", user.getEmail(), networks.size());
        }

        List<WiFiNetworkResponse> response = networks.stream()
                .map(this::toResponse)
                .collect(Collectors.toList());

        return ResponseEntity.ok(response);
    }

    /**
     * Get connected clients for a WiFi network (ADMIN only).
     * 
     * GET /api/wifi/{id}/clients
     */
    @GetMapping("/{id}/clients")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<List<ConnectedClientResponse>> getConnectedClients(@PathVariable String id) {
        WiFiNetwork network = wifiNetworkRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("WiFi Network", id));

        return ResponseEntity.ok(wifiScannerService.scanClients(network.getBssid(), network.getChannel()));
    }

    /**
     * Delete a WiFi network (ADMIN only).
     * 
     * DELETE /api/wifi/{id}
     */
    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional(readOnly = false)
    public ResponseEntity<Map<String, String>> deleteWiFiNetwork(@PathVariable String id) {
        logger.info("Delete request received for ID: {}", id);
        User user = getCurrentUser();
        Institute institute = user.getInstitute();

        WiFiNetwork network = wifiNetworkRepository.findById(id)
                .orElseThrow(() -> new ResourceNotFoundException("WiFi Network", id));

        // Verify network belongs to admin's institute
        if (!network.getInstitute().getInstituteId().equals(institute.getInstituteId())) {
            throw new UnauthorizedException("You can only delete networks from your own institute");
        }

        logger.info("Deleting WiFi network: {} by admin: {}", network.getSsid(), user.getEmail());

        // Delete user mappings first to avoid foreign key constraints
        List<UserWiFiMapping> mappings = userWiFiMappingRepository.findByWifiNetwork(network);
        if (!mappings.isEmpty()) {
            userWiFiMappingRepository.deleteAll(mappings);
        }

        wifiNetworkRepository.delete(network);
        wifiNetworkRepository.flush(); // Force flush to ensure DB constraints are checked immediately

        return ResponseEntity.ok(Map.of("message", "WiFi network deleted successfully"));
    }

    /**
     * Assign a WiFi network to a viewer (ADMIN only).
     * 
     * POST /api/wifi/assign-to-viewer
     */
    @PostMapping("/assign-to-viewer")
    @PreAuthorize("hasRole('ADMIN')")
    @Transactional
    public ResponseEntity<Map<String, String>> assignWiFiToViewer(
            @Valid @RequestBody AssignWiFiRequest request) {
        User admin = getCurrentUser();
        Institute institute = admin.getInstitute();

        // Find viewer
        User viewer = userRepository.findById(request.getViewerId())
                .orElseThrow(() -> new ResourceNotFoundException("Viewer", request.getViewerId()));

        // Verify viewer belongs to same institute
        if (!viewer.getInstitute().getInstituteId().equals(institute.getInstituteId())) {
            throw new UnauthorizedException("Viewer does not belong to your institute");
        }

        // Verify viewer is actually a viewer
        if (viewer.getRole() != UserRole.VIEWER) {
            throw new UnauthorizedException("Target user is not a viewer");
        }

        // Find WiFi network
        WiFiNetwork network = wifiNetworkRepository.findById(request.getWifiId())
                .orElseThrow(() -> new ResourceNotFoundException("WiFi Network", request.getWifiId()));

        // Verify network belongs to admin's institute
        if (!network.getInstitute().getInstituteId().equals(institute.getInstituteId())) {
            throw new UnauthorizedException("WiFi network does not belong to your institute");
        }

        // Check if already assigned
        if (userWiFiMappingRepository.existsByUserAndWifiNetwork(viewer, network)) {
            return ResponseEntity.ok(Map.of("message", "WiFi network already assigned to viewer"));
        }

        // Create mapping
        UserWiFiMapping mapping = UserWiFiMapping.builder()
                .mappingId(UUID.randomUUID().toString())
                .user(viewer)
                .wifiNetwork(network)
                .build();

        userWiFiMappingRepository.save(mapping);

        logger.info("Assigned WiFi {} to viewer {} by admin {}",
                network.getSsid(), viewer.getEmail(), admin.getEmail());

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(Map.of("message", "WiFi network assigned to viewer successfully"));
    }

    private User getCurrentUser() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        return userRepository.findByEmailWithInstitute(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", email));
    }

    private WiFiNetworkResponse toResponse(WiFiNetwork network) {
        User creator = network.getCreatedByUser();
        SecurityType secType = network.getSecurityType();

        return WiFiNetworkResponse.builder()
                .wifiId(network.getWifiId())
                .ssid(network.getSsid())
                .bssid(network.getBssid())
                .channel(network.getChannel())
                .securityType(secType != null ? secType.name() : "WPA2")
                .location(network.getLocation())
                .createdByUserId(creator != null ? creator.getUserId() : null)
                .createdByUserName(creator != null ? creator.getName() : null)
                .createdAt(network.getCreatedAt())
                .build();
    }
}
