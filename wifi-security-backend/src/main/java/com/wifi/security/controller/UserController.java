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
}
