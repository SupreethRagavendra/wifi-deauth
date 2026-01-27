package com.wifi.security.dto.request;

import com.wifi.security.enums.InstituteType;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for admin registration request.
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RegisterAdminRequest {

    @NotBlank(message = "Institute name is required")
    @Size(min = 2, max = 255, message = "Institute name must be between 2 and 255 characters")
    @Pattern(regexp = "^[^<>]*$", message = "Institute name must not contain special characters or HTML tags")
    private String instituteName;

    @NotNull(message = "Institute type is required")
    private InstituteType instituteType;

    @Size(max = 255, message = "Location must not exceed 255 characters")
    private String location;

    @NotBlank(message = "Admin name is required")
    @Size(min = 2, max = 100, message = "Name must be between 2 and 100 characters")
    @Pattern(regexp = "^[^<>]*$", message = "Name must not contain special characters or HTML tags")
    private String adminName;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    @NotBlank(message = "Password is required")
    @Size(min = 8, message = "Password must be at least 8 characters")
    @Pattern(regexp = "^(?=.*[A-Z])(?=.*[0-9]).{8,}$", message = "Password must contain at least 1 uppercase letter and 1 number")
    private String password;
}
