package com.wifi.security.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for admin registration response.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisterAdminResponse {

    private String message;
    private String instituteCode;
    private String userId;
    private String instituteName;
}
