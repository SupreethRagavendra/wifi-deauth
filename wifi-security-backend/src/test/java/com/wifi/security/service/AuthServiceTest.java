package com.wifi.security.service;

import com.wifi.security.config.JwtTokenProvider;
import com.wifi.security.dto.request.LoginRequest;
import com.wifi.security.dto.request.RegisterAdminRequest;
import com.wifi.security.dto.request.RegisterHomeRequest;
import com.wifi.security.dto.request.RegisterViewerRequest;
import com.wifi.security.dto.response.AuthResponse;
import com.wifi.security.dto.response.RegisterAdminResponse;
import com.wifi.security.dto.response.VerifyInstituteCodeResponse;
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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for AuthService.
 */
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private InstituteRepository instituteRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private JwtTokenProvider jwtTokenProvider;

    @Mock
    private InstituteCodeGenerator instituteCodeGenerator;

    @InjectMocks
    private AuthService authService;

    private RegisterAdminRequest adminRequest;
    private RegisterViewerRequest viewerRequest;
    private RegisterHomeRequest homeRequest;
    private LoginRequest loginRequest;
    private Institute testInstitute;
    private User testUser;

    @BeforeEach
    void setUp() {
        // Setup test data
        adminRequest = RegisterAdminRequest.builder()
                .instituteName("Test University")
                .instituteType(InstituteType.COLLEGE)
                .location("Test City")
                .adminName("John Admin")
                .email("admin@test.com")
                .password("Password123")
                .build();

        viewerRequest = RegisterViewerRequest.builder()
                .instituteCode("TEST2026ABCD")
                .name("Jane Viewer")
                .email("viewer@test.com")
                .password("Password123")
                .build();

        homeRequest = RegisterHomeRequest.builder()
                .name("Home User")
                .email("home@test.com")
                .password("Password123")
                .build();

        loginRequest = LoginRequest.builder()
                .email("admin@test.com")
                .password("Password123")
                .build();

        testInstitute = Institute.builder()
                .instituteId("inst-123")
                .instituteName("Test University")
                .instituteType(InstituteType.COLLEGE)
                .instituteCode("TEST2026ABCD")
                .build();

        testUser = User.builder()
                .userId("user-123")
                .name("John Admin")
                .email("admin@test.com")
                .passwordHash("hashedPassword")
                .role(UserRole.ADMIN)
                .institute(testInstitute)
                .build();
    }

    @Test
    @DisplayName("Register Admin - Success")
    void testRegisterAdmin_Success() {
        // Arrange
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(instituteCodeGenerator.generate(anyString(), any())).thenReturn("TEST2026ABCD");
        when(instituteRepository.save(any(Institute.class))).thenAnswer(i -> i.getArgument(0));
        when(userRepository.save(any(User.class))).thenAnswer(i -> {
            User user = i.getArgument(0);
            user.setUserId("user-123");
            return user;
        });
        when(passwordEncoder.encode(anyString())).thenReturn("hashedPassword");

        // Act
        RegisterAdminResponse response = authService.registerAdmin(adminRequest);

        // Assert
        assertNotNull(response);
        assertEquals("Admin registered successfully", response.getMessage());
        assertEquals("TEST2026ABCD", response.getInstituteCode());
        assertNotNull(response.getUserId());

        verify(userRepository).existsByEmail("admin@test.com");
        verify(instituteRepository).save(any(Institute.class));
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("Register Admin - Duplicate Email")
    void testRegisterAdmin_DuplicateEmail() {
        // Arrange
        when(userRepository.existsByEmail(anyString())).thenReturn(true);

        // Act & Assert
        assertThrows(DuplicateEmailException.class, () -> {
            authService.registerAdmin(adminRequest);
        });

        verify(userRepository).existsByEmail("admin@test.com");
        verify(instituteRepository, never()).save(any());
        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("Register Viewer - Success")
    void testRegisterViewer_Success() {
        // Arrange
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(instituteRepository.findByInstituteCode("TEST2026ABCD")).thenReturn(Optional.of(testInstitute));
        when(userRepository.save(any(User.class))).thenAnswer(i -> {
            User user = i.getArgument(0);
            user.setUserId("viewer-123");
            return user;
        });
        when(passwordEncoder.encode(anyString())).thenReturn("hashedPassword");
        when(jwtTokenProvider.generateToken(anyString(), anyString(), anyString(), anyString()))
                .thenReturn("test-jwt-token");

        // Act
        AuthResponse response = authService.registerViewer(viewerRequest);

        // Assert
        assertNotNull(response);
        assertEquals("test-jwt-token", response.getToken());
        assertEquals("VIEWER", response.getRole());
        assertEquals("Test University", response.getInstituteName());

        verify(instituteRepository).findByInstituteCode("TEST2026ABCD");
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("Register Viewer - Invalid Institute Code")
    void testRegisterViewer_InvalidCode() {
        // Arrange
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(instituteRepository.findByInstituteCode("TEST2026ABCD")).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(InvalidInstituteCodeException.class, () -> {
            authService.registerViewer(viewerRequest);
        });

        verify(userRepository, never()).save(any());
    }

    @Test
    @DisplayName("Register Home User - Success")
    void testRegisterHome_Success() {
        // Arrange
        when(userRepository.existsByEmail(anyString())).thenReturn(false);
        when(instituteRepository.save(any(Institute.class))).thenAnswer(i -> {
            Institute inst = i.getArgument(0);
            inst.setInstituteId("home-inst-123");
            return inst;
        });
        when(userRepository.save(any(User.class))).thenAnswer(i -> {
            User user = i.getArgument(0);
            user.setUserId("home-user-123");
            return user;
        });
        when(passwordEncoder.encode(anyString())).thenReturn("hashedPassword");
        when(jwtTokenProvider.generateToken(anyString(), anyString(), anyString(), anyString()))
                .thenReturn("home-jwt-token");

        // Act
        AuthResponse response = authService.registerHome(homeRequest);

        // Assert
        assertNotNull(response);
        assertEquals("home-jwt-token", response.getToken());
        assertEquals("ADMIN", response.getRole()); // Home users are admins
        assertEquals("HOME", response.getInstituteType());
        assertNull(response.getInstituteCode()); // No code for home

        verify(instituteRepository).save(any(Institute.class));
        verify(userRepository).save(any(User.class));
    }

    @Test
    @DisplayName("Login - Success")
    void testLogin_Success() {
        // Arrange
        when(userRepository.findByEmail("admin@test.com")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("Password123", "hashedPassword")).thenReturn(true);
        when(jwtTokenProvider.generateToken(anyString(), anyString(), anyString(), anyString()))
                .thenReturn("login-jwt-token");

        // Act
        AuthResponse response = authService.login(loginRequest);

        // Assert
        assertNotNull(response);
        assertEquals("login-jwt-token", response.getToken());
        assertEquals("ADMIN", response.getRole());
        assertEquals("admin@test.com", response.getEmail());

        verify(userRepository).findByEmail("admin@test.com");
        verify(passwordEncoder).matches("Password123", "hashedPassword");
    }

    @Test
    @DisplayName("Login - Wrong Password")
    void testLogin_WrongPassword() {
        // Arrange
        when(userRepository.findByEmail("admin@test.com")).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches("Password123", "hashedPassword")).thenReturn(false);

        // Act & Assert
        assertThrows(InvalidCredentialsException.class, () -> {
            authService.login(loginRequest);
        });

        verify(jwtTokenProvider, never()).generateToken(any(), any(), any(), any());
    }

    @Test
    @DisplayName("Login - User Not Found")
    void testLogin_UserNotFound() {
        // Arrange
        when(userRepository.findByEmail("admin@test.com")).thenReturn(Optional.empty());

        // Act & Assert
        assertThrows(InvalidCredentialsException.class, () -> {
            authService.login(loginRequest);
        });
    }

    @Test
    @DisplayName("Verify Institute Code - Valid")
    void testVerifyInstituteCode_Valid() {
        // Arrange
        when(instituteRepository.findByInstituteCode("TEST2026ABCD")).thenReturn(Optional.of(testInstitute));

        // Act
        VerifyInstituteCodeResponse response = authService.verifyInstituteCode("TEST2026ABCD");

        // Assert
        assertTrue(response.isValid());
        assertEquals("Test University", response.getInstituteName());
        assertEquals("COLLEGE", response.getInstituteType());
    }

    @Test
    @DisplayName("Verify Institute Code - Invalid")
    void testVerifyInstituteCode_Invalid() {
        // Arrange
        when(instituteRepository.findByInstituteCode("INVALID")).thenReturn(Optional.empty());

        // Act
        VerifyInstituteCodeResponse response = authService.verifyInstituteCode("INVALID");

        // Assert
        assertFalse(response.isValid());
        assertNull(response.getInstituteName());
    }
}
