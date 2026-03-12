package com.wifi.security.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for authentication response (login/register).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class AuthResponse {

    private String token;
    private String userId;
    private String email;
    private String name;
    private String role;
    private String instituteName;
    private String instituteCode;
    private String instituteType;
    private String macAddress;
    private String message;
}
