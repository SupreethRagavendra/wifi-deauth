package com.wifi.security.util;

import java.util.regex.Pattern;

/**
 * Utility class for password operations.
 */
public class PasswordUtil {

    // Password must have at least 8 characters, 1 uppercase, 1 number
    private static final Pattern STRONG_PASSWORD_PATTERN = Pattern.compile(
            "^(?=.*[A-Z])(?=.*[0-9]).{8,}$");

    private PasswordUtil() {
        // Private constructor to prevent instantiation
    }

    /**
     * Check if a password meets the strength requirements.
     * Requirements:
     * - Minimum 8 characters
     * - At least 1 uppercase letter
     * - At least 1 number
     * 
     * @param password The password to validate
     * @return true if password is strong, false otherwise
     */
    public static boolean isStrongPassword(String password) {
        if (password == null || password.isBlank()) {
            return false;
        }
        return STRONG_PASSWORD_PATTERN.matcher(password).matches();
    }

    /**
     * Get password strength requirements as a message.
     * 
     * @return String describing password requirements
     */
    public static String getPasswordRequirements() {
        return "Password must be at least 8 characters with 1 uppercase letter and 1 number";
    }
}
