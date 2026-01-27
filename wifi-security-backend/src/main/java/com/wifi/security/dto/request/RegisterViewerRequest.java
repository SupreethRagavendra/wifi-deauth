package com.wifi.security.dto.request;

import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for viewer registration request.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisterViewerRequest {

    @NotBlank(message = "Institute code is required")
    @Pattern(regexp = "^[A-Z0-9]{8,20}$", message = "Invalid institute code format")
    private String instituteCode;

    @NotBlank(message = "Name is required")
    @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    private String name;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(regexp = "^(?=.*[A-Z])(?=.*[0-9]).{8,}$", message = "Password must contain at least 1 uppercase letter and 1 number")
    private String password;
}
