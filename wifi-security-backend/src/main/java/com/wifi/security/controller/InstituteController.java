package com.wifi.security.controller;

import com.wifi.security.dto.response.VerifyInstituteCodeResponse;
import com.wifi.security.entity.Institute;
import com.wifi.security.entity.User;
import com.wifi.security.exception.ResourceNotFoundException;
import com.wifi.security.repository.InstituteRepository;
import com.wifi.security.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

/**
 * Controller for institute-related endpoints.
 */
@RestController
@RequestMapping("/api/institutes")
@CrossOrigin(origins = { "http://localhost:3000", "http://localhost:5173" })
public class InstituteController {

    private static final Logger logger = LoggerFactory.getLogger(InstituteController.class);

    private final InstituteRepository instituteRepository;
    private final UserRepository userRepository;

    public InstituteController(InstituteRepository instituteRepository,
            UserRepository userRepository) {
        this.instituteRepository = instituteRepository;
        this.userRepository = userRepository;
    }

    /**
     * Get current user's institute details.
     * 
     * GET /api/institutes/my
     */
    @GetMapping("/my")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Map<String, Object>> getMyInstitute() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String email = authentication.getName();

        logger.debug("Fetching institute for user: {}", email);

        User user = userRepository.findByEmailWithInstitute(email)
                .orElseThrow(() -> new ResourceNotFoundException("User", email));

        Institute institute = user.getInstitute();
        if (institute == null) {
            throw new ResourceNotFoundException("Institute", "not found for user");
        }

        Map<String, Object> response = new HashMap<>();
        response.put("instituteId", institute.getInstituteId());
        response.put("instituteName", institute.getInstituteName());
        response.put("instituteType", institute.getInstituteType().name());
        response.put("instituteCode", institute.getInstituteCode());
        response.put("location", institute.getLocation());
        response.put("createdAt", institute.getCreatedAt());

        return ResponseEntity.ok(response);
    }

    /**
     * Verify institute code (public endpoint).
     * 
     * GET /api/institutes/{code}/verify
     */
    @GetMapping("/{code}/verify")
    public ResponseEntity<VerifyInstituteCodeResponse> verifyInstituteCode(
            @PathVariable String code) {
        logger.debug("Verifying institute code: {}", code);

        return instituteRepository.findByInstituteCode(code)
                .map(institute -> ResponseEntity.ok(VerifyInstituteCodeResponse.builder()
                        .valid(true)
                        .instituteName(institute.getInstituteName())
                        .instituteType(institute.getInstituteType().name())
                        .build()))
                .orElse(ResponseEntity.ok(VerifyInstituteCodeResponse.builder()
                        .valid(false)
                        .instituteName(null)
                        .instituteType(null)
                        .build()));
    }
}
