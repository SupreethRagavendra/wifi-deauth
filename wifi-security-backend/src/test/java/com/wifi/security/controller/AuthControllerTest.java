package com.wifi.security.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wifi.security.dto.request.LoginRequest;
import com.wifi.security.dto.request.RegisterAdminRequest;
import com.wifi.security.dto.request.VerifyInstituteCodeRequest;
import com.wifi.security.dto.response.AuthResponse;
import com.wifi.security.dto.response.RegisterAdminResponse;
import com.wifi.security.dto.response.VerifyInstituteCodeResponse;
import com.wifi.security.enums.InstituteType;
import com.wifi.security.service.AuthService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for AuthController.
 */
@SpringBootTest
@AutoConfigureMockMvc
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthService authService;

    @Test
    @DisplayName("POST /api/auth/register/admin - Success")
    void testRegisterAdminEndpoint() throws Exception {
        // Arrange
        RegisterAdminRequest request = RegisterAdminRequest.builder()
                .instituteName("Test College")
                .instituteType(InstituteType.COLLEGE)
                .adminName("Admin User")
                .email("admin@test.com")
                .password("Password123")
                .build();

        RegisterAdminResponse response = RegisterAdminResponse.builder()
                .message("Admin registered successfully")
                .instituteCode("TEST2026ABCD")
                .userId("user-123")
                .instituteName("Test College")
                .build();

        when(authService.registerAdmin(any())).thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/auth/register/admin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.instituteCode").value("TEST2026ABCD"))
                .andExpect(jsonPath("$.message").value("Admin registered successfully"));
    }

    @Test
    @DisplayName("POST /api/auth/login - Success")
    void testLoginEndpoint() throws Exception {
        // Arrange
        LoginRequest request = LoginRequest.builder()
                .email("admin@test.com")
                .password("Password123")
                .build();

        AuthResponse response = AuthResponse.builder()
                .token("jwt-token-here")
                .userId("user-123")
                .email("admin@test.com")
                .role("ADMIN")
                .message("Login successful")
                .build();

        when(authService.login(any())).thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/auth/login")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").value("jwt-token-here"))
                .andExpect(jsonPath("$.role").value("ADMIN"));
    }

    @Test
    @DisplayName("POST /api/auth/verify-institute-code - Valid Code")
    void testVerifyInstituteCode() throws Exception {
        // Arrange
        VerifyInstituteCodeRequest request = VerifyInstituteCodeRequest.builder()
                .instituteCode("TEST2026ABCD")
                .build();

        VerifyInstituteCodeResponse response = VerifyInstituteCodeResponse.builder()
                .valid(true)
                .instituteName("Test College")
                .instituteType("COLLEGE")
                .build();

        when(authService.verifyInstituteCode(any())).thenReturn(response);

        // Act & Assert
        mockMvc.perform(post("/api/auth/verify-institute-code")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.valid").value(true))
                .andExpect(jsonPath("$.instituteName").value("Test College"));
    }

    @Test
    @DisplayName("POST /api/auth/register/admin - Validation Error")
    void testRegisterAdminValidationError() throws Exception {
        // Arrange - invalid request (missing required fields)
        RegisterAdminRequest request = RegisterAdminRequest.builder()
                .email("invalid-email") // Invalid email format
                .password("weak") // Password too weak
                .build();

        // Act & Assert
        mockMvc.perform(post("/api/auth/register/admin")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest());
    }
}
