package com.wifi.security.controller;

import com.wifi.security.dto.response.UserProfileResponse;
import com.wifi.security.entity.Institute;
import com.wifi.security.entity.User;
import com.wifi.security.enums.UserRole;
import com.wifi.security.exception.ResourceNotFoundException;
import com.wifi.security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Controller for user-related endpoints.
 */
@RestController
@RequestMapping("/api/users")
@CrossOrigin(origins = { "http://localhost:3000", "http://localhost:5173" })
public class UserController {

        private static final Logger logger = LoggerFactory.getLogger(UserController.class);

        private final UserRepository userRepository;

        public UserController(UserRepository userRepository) {
                this.userRepository = userRepository;
        }

        /**
         * Get current authenticated user's profile.
         * 
         * GET /api/users/me
         */
        @GetMapping("/me")
        @PreAuthorize("isAuthenticated()")
        public ResponseEntity<UserProfileResponse> getCurrentUser() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                String email = authentication.getName();

                logger.debug("Fetching profile for user: {}", email);

                User user = userRepository.findByEmailWithInstitute(email)
                                .orElseThrow(() -> new ResourceNotFoundException("User", email));

                Institute institute = user.getInstitute();

                UserProfileResponse response = UserProfileResponse.builder()
                                .userId(user.getUserId())
                                .name(user.getName())
                                .email(user.getEmail())
                                .role(user.getRole().name())
                                .instituteName(institute != null ? institute.getInstituteName() : null)
                                .instituteCode(institute != null ? institute.getInstituteCode() : null)
                                .instituteType(institute != null ? institute.getInstituteType().name() : null)
                                .macAddress(user.getMacAddress())
                                .wifiAdapter(user.getWifiAdapter())
                                .phoneNumber(user.getPhoneNumber())
                                .alertsEmail(user.getAlertsEmail())
                                .alertsSms(user.getAlertsSms())
                                .createdAt(user.getCreatedAt())
                                .build();

                return ResponseEntity.ok(response);
        }

        /**
         * Get all viewers in the admin's institute.
         * 
         * GET /api/users/viewers
         */
        @GetMapping("/viewers")
        @PreAuthorize("hasRole('ADMIN')")
        public ResponseEntity<List<UserProfileResponse>> getViewers() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                String email = authentication.getName();

                logger.debug("Fetching viewers for admin: {}", email);

                User admin = userRepository.findByEmailWithInstitute(email)
                                .orElseThrow(() -> new ResourceNotFoundException("User", email));

                Institute institute = admin.getInstitute();
                if (institute == null) {
                        return ResponseEntity.ok(List.of());
                }

                List<User> viewers = userRepository.findByInstituteAndRole(institute, UserRole.VIEWER);

                List<UserProfileResponse> response = viewers.stream()
                                .map(viewer -> UserProfileResponse.builder()
                                                .userId(viewer.getUserId())
                                                .name(viewer.getName())
                                                .email(viewer.getEmail())
                                                .role(viewer.getRole().name())
                                                .instituteName(institute.getInstituteName())
                                                .instituteCode(institute.getInstituteCode())
                                                .instituteType(institute.getInstituteType().name())
                                                .createdAt(viewer.getCreatedAt())
                                                .build())
                                .collect(Collectors.toList());

                return ResponseEntity.ok(response);
        }

        // DTO for update MAC address request
        public static class UpdateMacRequest {
                private String macAddress;

                public String getMacAddress() {
                        return macAddress;
                }

                public void setMacAddress(String macAddress) {
                        this.macAddress = macAddress;
                }
        }

        /**
         * Update current user's MAC address.
         * 
         * PUT /api/users/mac-address
         */
        @PutMapping("/mac-address")
        @PreAuthorize("isAuthenticated()")
        @org.springframework.transaction.annotation.Transactional
        public ResponseEntity<UserProfileResponse> updateMacAddress(@RequestBody UpdateMacRequest request) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                String email = authentication.getName();

                logger.debug("Updating MAC address for user: {}", email);

                User user = userRepository.findByEmailWithInstitute(email)
                                .orElseThrow(() -> new ResourceNotFoundException("User", email));

                if (request.getMacAddress() != null && !request.getMacAddress().trim().isEmpty()) {
                        // Basic validation
                        String mac = request.getMacAddress().trim().toUpperCase();
                        if (!mac.matches("^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")) {
                                throw new IllegalArgumentException("Invalid MAC address format");
                        }

                        // Check uniqueness — no other user should have this MAC
                        Optional<User> existingOwner = userRepository.findByMacAddress(mac);
                        if (existingOwner.isPresent() && !existingOwner.get().getUserId().equals(user.getUserId())) {
                                return ResponseEntity.status(org.springframework.http.HttpStatus.CONFLICT)
                                                .body(UserProfileResponse.builder()
                                                                .userId(existingOwner.get().getUserId())
                                                                .name(existingOwner.get().getName())
                                                                .email(existingOwner.get().getEmail())
                                                                .macAddress(mac)
                                                                .build());
                        }

                        user.setMacAddress(mac);
                } else {
                        user.setMacAddress(null);
                }

                user = userRepository.save(user);
                Institute institute = user.getInstitute();

                UserProfileResponse response = UserProfileResponse.builder()
                                .userId(user.getUserId())
                                .name(user.getName())
                                .email(user.getEmail())
                                .role(user.getRole().name())
                                .instituteName(institute != null ? institute.getInstituteName() : null)
                                .instituteCode(institute != null ? institute.getInstituteCode() : null)
                                .instituteType(institute != null ? institute.getInstituteType().name() : null)
                                .macAddress(user.getMacAddress())
                                .wifiAdapter(user.getWifiAdapter())
                                .phoneNumber(user.getPhoneNumber())
                                .alertsEmail(user.getAlertsEmail())
                                .alertsSms(user.getAlertsSms())
                                .createdAt(user.getCreatedAt())
                                .build();

                return ResponseEntity.ok(response);
        }

        /**
         * Update current user's WiFi adapter.
         * PUT /api/users/me/adapter
         */
        @PutMapping("/me/adapter")
        @PreAuthorize("isAuthenticated()")
        @org.springframework.transaction.annotation.Transactional
        public ResponseEntity<java.util.Map<String, String>> updateAdapter(
                        @RequestBody java.util.Map<String, String> body) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                String email = authentication.getName();
                User user = userRepository.findByEmailWithInstitute(email)
                                .orElseThrow(() -> new ResourceNotFoundException("User", email));

                String adapter = body.getOrDefault("wifiAdapter", "wlan1").trim();
                if (!adapter.matches("^wlan\\d+$")) {
                        return ResponseEntity.badRequest().body(
                                        java.util.Map.of("error", "Invalid adapter name. Use wlan0, wlan1, etc."));
                }
                user.setWifiAdapter(adapter);
                userRepository.save(user);
                return ResponseEntity.ok(java.util.Map.of("wifiAdapter", adapter, "message", "WiFi adapter updated"));
        }

        /**
         * Update current user's phone number.
         * PUT /api/users/me/phone
         */
        @PutMapping("/me/phone")
        @PreAuthorize("isAuthenticated()")
        @org.springframework.transaction.annotation.Transactional
        public ResponseEntity<java.util.Map<String, String>> updatePhone(
                        @RequestBody java.util.Map<String, String> body) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                String email = authentication.getName();
                User user = userRepository.findByEmailWithInstitute(email)
                                .orElseThrow(() -> new ResourceNotFoundException("User", email));

                String phone = body.getOrDefault("phoneNumber", "").trim();
                if (!phone.isEmpty() && !phone.matches("^[0-9]{10,15}$")) {
                        return ResponseEntity.badRequest().body(java.util.Map.of("error", "Invalid phone number"));
                }
                user.setPhoneNumber(phone.isEmpty() ? null : phone);
                userRepository.save(user);
                return ResponseEntity.ok(java.util.Map.of("phoneNumber", phone, "message", "Phone number updated"));
        }

        /**
         * Update current user's alert preferences.
         * PUT /api/users/me/alert-preferences
         */
        @PutMapping("/me/alert-preferences")
        @PreAuthorize("isAuthenticated()")
        @org.springframework.transaction.annotation.Transactional
        public ResponseEntity<java.util.Map<String, Object>> updateAlertPreferences(
                        @RequestBody java.util.Map<String, Object> body) {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
                String email = authentication.getName();
                User user = userRepository.findByEmailWithInstitute(email)
                                .orElseThrow(() -> new ResourceNotFoundException("User", email));

                if (body.containsKey("alertsEmail")) {
                        user.setAlertsEmail(Boolean.valueOf(body.get("alertsEmail").toString()));
                }
                if (body.containsKey("alertsSms")) {
                        user.setAlertsSms(Boolean.valueOf(body.get("alertsSms").toString()));
                }
                userRepository.save(user);

                java.util.Map<String, Object> result = new java.util.HashMap<>();
                result.put("alertsEmail", user.getAlertsEmail());
                result.put("alertsSms", user.getAlertsSms());
                result.put("message", "Alert preferences updated");
                return ResponseEntity.ok(result);
        }
}
