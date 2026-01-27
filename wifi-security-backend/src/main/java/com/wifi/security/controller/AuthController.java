package com.wifi.security.controller;

import com.wifi.security.dto.request.*;
import com.wifi.security.dto.response.*;
import com.wifi.security.service.AuthService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Controller for authentication endpoints.
 * Handles registration (Admin, Viewer, Home) and login.
 */
@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = { "http://localhost:3000", "http://localhost:5173" })
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    /**
     * Register a new admin with a new institute.
     * 
     * POST /api/auth/register/admin
     */
    @PostMapping("/register/admin")
    public ResponseEntity<RegisterAdminResponse> registerAdmin(
            @Valid @RequestBody RegisterAdminRequest request) {
        logger.info("Admin registration request received for: {}", request.getEmail());

        RegisterAdminResponse response = authService.registerAdmin(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Register a new viewer for an existing institute.
     * 
     * POST /api/auth/register/viewer
     */
    @PostMapping("/register/viewer")
    public ResponseEntity<AuthResponse> registerViewer(
            @Valid @RequestBody RegisterViewerRequest request) {
        logger.info("Viewer registration request received for: {}", request.getEmail());

        AuthResponse response = authService.registerViewer(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Register a home user (personal use).
     * 
     * POST /api/auth/register/home
     */
    @PostMapping("/register/home")
    public ResponseEntity<AuthResponse> registerHome(
            @Valid @RequestBody RegisterHomeRequest request) {
        logger.info("Home user registration request received for: {}", request.getEmail());

        AuthResponse response = authService.registerHome(request);

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    /**
     * Authenticate a user and return a JWT token.
     * 
     * POST /api/auth/login
     */
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody LoginRequest request) {
        logger.info("Login request received for: {}", request.getEmail());

        AuthResponse response = authService.login(request);

        return ResponseEntity.ok(response);
    }

    /**
     * Verify if an institute code is valid.
     * 
     * POST /api/auth/verify-institute-code
     */
    @PostMapping("/verify-institute-code")
    public ResponseEntity<VerifyInstituteCodeResponse> verifyInstituteCode(
            @Valid @RequestBody VerifyInstituteCodeRequest request) {
        logger.debug("Verify institute code request: {}", request.getInstituteCode());

        VerifyInstituteCodeResponse response = authService.verifyInstituteCode(request.getInstituteCode());

        return ResponseEntity.ok(response);
    }
}
