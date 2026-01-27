package com.wifi.security.dto.response;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for institute code verification response.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerifyInstituteCodeResponse {

    private boolean valid;
    private String instituteName;
    private String instituteType;
}
