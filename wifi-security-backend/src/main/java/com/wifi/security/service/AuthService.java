package com.wifi.security.service;

import com.wifi.security.config.JwtTokenProvider;
import com.wifi.security.dto.request.*;
import com.wifi.security.dto.response.*;
import com.wifi.security.entity.Institute;
import com.wifi.security.entity.User;
import com.wifi.security.enums.InstituteType;
import com.wifi.security.enums.UserRole;
import com.wifi.security.exception.DuplicateEmailException;
import com.wifi.security.exception.InvalidCredentialsException;
import com.wifi.security.exception.InvalidInstituteCodeException;
import com.wifi.security.repository.InstituteRepository;
import com.wifi.security.repository.UserRepository;
import com.wifi.security.util.InstituteCodeGenerator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/**
 * Service for authentication operations.
 * Handles registration (Admin, Viewer, Home) and login.
 */
@Service
public class AuthService {

        private static final Logger logger = LoggerFactory.getLogger(AuthService.class);

        private final UserRepository userRepository;
        private final InstituteRepository instituteRepository;
        private final PasswordEncoder passwordEncoder;
        private final JwtTokenProvider jwtTokenProvider;
        private final InstituteCodeGenerator instituteCodeGenerator;

        public AuthService(UserRepository userRepository,
                        InstituteRepository instituteRepository,
                        PasswordEncoder passwordEncoder,
                        JwtTokenProvider jwtTokenProvider,
                        InstituteCodeGenerator instituteCodeGenerator) {
                this.userRepository = userRepository;
                this.instituteRepository = instituteRepository;
                this.passwordEncoder = passwordEncoder;
                this.jwtTokenProvider = jwtTokenProvider;
                this.instituteCodeGenerator = instituteCodeGenerator;
        }

        /**
         * Register a new admin user with a new institute.
         * Handles concurrent registration attempts with synchronized email check.
         * 
         * @param request The registration request
         * @return Registration response with institute code
         */
        @Transactional
        public synchronized RegisterAdminResponse registerAdmin(RegisterAdminRequest request) {
                logger.info("Registering admin for institute: {}", request.getInstituteName());

                // Check if email already exists
                if (userRepository.existsByEmail(request.getEmail())) {
                        logger.warn("Registration failed - duplicate email: {}", request.getEmail());
                        throw new DuplicateEmailException("Email already registered: " + request.getEmail());
                }

                // Generate unique institute code
                String instituteCode = instituteCodeGenerator.generate(
                                request.getInstituteName(),
                                request.getInstituteType());

                // Create institute
                Institute institute = Institute.builder()
                                .instituteId(UUID.randomUUID().toString())
                                .instituteName(request.getInstituteName().trim())
                                .instituteType(request.getInstituteType())
                                .instituteCode(instituteCode)
                                .location(request.getLocation() != null ? request.getLocation().trim() : null)
                                .build();

                institute = instituteRepository.save(institute);
                logger.info("Created institute: {} with code: {}", institute.getInstituteName(), instituteCode);

                // Create admin user
                User admin = User.builder()
                                .userId(UUID.randomUUID().toString())
                                .institute(institute)
                                .name(request.getAdminName().trim())
                                .email(request.getEmail().trim().toLowerCase())
                                .passwordHash(passwordEncoder.encode(request.getPassword()))
                                .role(UserRole.ADMIN)
                                .build();

                admin = userRepository.save(admin);
                logger.info("Admin registration successful: email={}, institute={}",
                                request.getEmail(), request.getInstituteName());

                return RegisterAdminResponse.builder()
                                .message("Admin registered successfully")
                                .instituteCode(instituteCode)
                                .userId(admin.getUserId())
                                .instituteName(institute.getInstituteName())
                                .build();
        }

        /**
         * Register a new viewer user for an existing institute.
         * 
         * @param request The registration request
         * @return Auth response with token
         */
        @Transactional
        public AuthResponse registerViewer(RegisterViewerRequest request) {
                logger.info("Registering viewer with institute code: {}", request.getInstituteCode());

                // Check if email already exists
                if (userRepository.existsByEmail(request.getEmail())) {
                        logger.warn("Registration failed - duplicate email: {}", request.getEmail());
                        throw new DuplicateEmailException("Email already registered: " + request.getEmail());
                }

                // Find institute by code
                Institute institute = instituteRepository.findByInstituteCode(request.getInstituteCode())
                                .orElseThrow(() -> {
                                        logger.warn("Registration failed - invalid institute code: {}",
                                                        request.getInstituteCode());
                                        return new InvalidInstituteCodeException(
                                                        "Invalid institute code: " + request.getInstituteCode());
                                });

                // Create viewer user
                User viewer = User.builder()
                                .userId(UUID.randomUUID().toString())
                                .institute(institute)
                                .name(request.getName().trim())
                                .email(request.getEmail().trim().toLowerCase())
                                .passwordHash(passwordEncoder.encode(request.getPassword()))
                                .role(UserRole.VIEWER)
                                .build();

                viewer = userRepository.save(viewer);
                logger.info("Viewer registration successful: email={}, institute={}",
                                request.getEmail(), institute.getInstituteName());

                // Generate token
                String token = jwtTokenProvider.generateToken(
                                viewer.getEmail(),
                                viewer.getRole().name(),
                                institute.getInstituteId(),
                                viewer.getUserId());

                return AuthResponse.builder()
                                .token(token)
                                .userId(viewer.getUserId())
                                .email(viewer.getEmail())
                                .name(viewer.getName())
                                .role(viewer.getRole().name())
                                .instituteName(institute.getInstituteName())
                                .instituteCode(institute.getInstituteCode())
                                .instituteType(institute.getInstituteType().name())
                                .message("Viewer registered successfully")
                                .build();
        }

        /**
         * Register a home user (creates a personal "institute").
         * 
         * @param request The registration request
         * @return Auth response with token
         */
        @Transactional
        public AuthResponse registerHome(RegisterHomeRequest request) {
                logger.info("Registering home user: {}", request.getEmail());

                // Check if email already exists
                if (userRepository.existsByEmail(request.getEmail())) {
                        logger.warn("Registration failed - duplicate email: {}", request.getEmail());
                        throw new DuplicateEmailException("Email already registered: " + request.getEmail());
                }

                // Create home "institute" (personal, no code needed for sharing)
                String homeName = request.getName().trim() + "'s Home Network";
                Institute homeInstitute = Institute.builder()
                                .instituteId(UUID.randomUUID().toString())
                                .instituteName(homeName)
                                .instituteType(InstituteType.HOME)
                                .instituteCode(null) // Home users don't have shareable codes
                                .location(null)
                                .build();

                homeInstitute = instituteRepository.save(homeInstitute);
                logger.info("Created home institute for: {}", request.getEmail());

                // Create home user (as ADMIN role for full control)
                User homeUser = User.builder()
                                .userId(UUID.randomUUID().toString())
                                .institute(homeInstitute)
                                .name(request.getName().trim())
                                .email(request.getEmail().trim().toLowerCase())
                                .passwordHash(passwordEncoder.encode(request.getPassword()))
                                .role(UserRole.HOME_USER) // Home users have their own role for proper routing
                                .build();

                homeUser = userRepository.save(homeUser);
                logger.info("Home user registration successful: email={}", request.getEmail());

                // Generate token
                String token = jwtTokenProvider.generateToken(
                                homeUser.getEmail(),
                                homeUser.getRole().name(),
                                homeInstitute.getInstituteId(),
                                homeUser.getUserId());

                return AuthResponse.builder()
                                .token(token)
                                .userId(homeUser.getUserId())
                                .email(homeUser.getEmail())
                                .name(homeUser.getName())
                                .role(homeUser.getRole().name())
                                .instituteName(homeInstitute.getInstituteName())
                                .instituteCode(null) // No code for home
                                .instituteType(InstituteType.HOME.name())
                                .message("Home user registered successfully")
                                .build();
        }

        /**
         * Authenticate a user and return a JWT token.
         * 
         * @param request Login credentials
         * @return Auth response with token
         */
        @Transactional(readOnly = true)
        public AuthResponse login(LoginRequest request) {
                logger.info("Login attempt for: {}", request.getEmail());

                // Find user by email
                User user = userRepository.findByEmail(request.getEmail().trim().toLowerCase())
                                .orElseThrow(() -> {
                                        logger.warn("Failed login attempt - user not found: {}", request.getEmail());
                                        return new InvalidCredentialsException("Invalid email or password");
                                });

                // Verify password
                if (!passwordEncoder.matches(request.getPassword(), user.getPasswordHash())) {
                        logger.warn("Failed login attempt - wrong password: {}", request.getEmail());
                        throw new InvalidCredentialsException("Invalid email or password");
                }

                // Get institute info
                Institute institute = user.getInstitute();
                String instituteId = institute != null ? institute.getInstituteId() : null;

                // Generate token
                String token = jwtTokenProvider.generateToken(
                                user.getEmail(),
                                user.getRole().name(),
                                instituteId,
                                user.getUserId());

                logger.info("Login successful: email={}, role={}", user.getEmail(), user.getRole());

                return AuthResponse.builder()
                                .token(token)
                                .userId(user.getUserId())
                                .email(user.getEmail())
                                .name(user.getName())
                                .role(user.getRole().name())
                                .instituteName(institute != null ? institute.getInstituteName() : null)
                                .instituteCode(institute != null ? institute.getInstituteCode() : null)
                                .instituteType(institute != null ? institute.getInstituteType().name() : null)
                                .message("Login successful")
                                .build();
        }

        /**
         * Verify if an institute code is valid.
         * 
         * @param code The institute code to verify
         * @return Verification response
         */
        @Transactional(readOnly = true)
        public VerifyInstituteCodeResponse verifyInstituteCode(String code) {
                logger.debug("Verifying institute code: {}", code);

                return instituteRepository.findByInstituteCode(code)
                                .map(institute -> VerifyInstituteCodeResponse.builder()
                                                .valid(true)
                                                .instituteName(institute.getInstituteName())
                                                .instituteType(institute.getInstituteType().name())
                                                .build())
                                .orElse(VerifyInstituteCodeResponse.builder()
                                                .valid(false)
                                                .instituteName(null)
                                                .instituteType(null)
                                                .build());
        }
}
