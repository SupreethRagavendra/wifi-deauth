package com.wifi.security.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.LocalDateTime;

/**
 * DTO for user profile response (without sensitive data).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class UserProfileResponse {

    private String userId;
    private String name;
    private String email;
    private String role;
    private String instituteName;
    private String instituteCode;
    private String instituteType;
    private LocalDateTime createdAt;
}
