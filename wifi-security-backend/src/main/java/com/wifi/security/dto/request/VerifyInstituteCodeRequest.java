package com.wifi.security.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for verifying institute code.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class VerifyInstituteCodeRequest {

    @NotBlank(message = "Institute code is required")
    @Pattern(regexp = "^[A-Z0-9]{8,20}$", message = "Invalid institute code format")
    private String instituteCode;
}
