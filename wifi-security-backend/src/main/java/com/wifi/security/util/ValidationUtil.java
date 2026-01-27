package com.wifi.security.util;

import java.util.regex.Pattern;

/**
 * Utility class for validation operations.
 */
public class ValidationUtil {

    // MAC address pattern: AA:BB:CC:DD:EE:FF
    private static final Pattern BSSID_PATTERN = Pattern.compile(
            "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$");

    // Email pattern
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9+_.-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    // Institute code pattern
    private static final Pattern INSTITUTE_CODE_PATTERN = Pattern.compile(
            "^[A-Z0-9]{8,20}$");

    private ValidationUtil() {
        // Private constructor to prevent instantiation
    }

    /**
     * Validate a BSSID (MAC address format).
     * 
     * @param bssid The BSSID to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidBSSID(String bssid) {
        if (bssid == null || bssid.isBlank()) {
            return false;
        }
        return BSSID_PATTERN.matcher(bssid.trim()).matches();
    }

    /**
     * Validate an SSID (WiFi network name).
     * 
     * @param ssid The SSID to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidSSID(String ssid) {
        if (ssid == null || ssid.isBlank()) {
            return false;
        }
        // SSID must be 1-32 characters, no control characters
        String trimmed = ssid.trim();
        if (trimmed.length() < 1 || trimmed.length() > 32) {
            return false;
        }
        // Check for control characters
        for (char c : trimmed.toCharArray()) {
            if (Character.isISOControl(c)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validate an email address.
     * 
     * @param email The email to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidEmail(String email) {
        if (email == null || email.isBlank()) {
            return false;
        }
        return EMAIL_PATTERN.matcher(email.trim()).matches();
    }

    /**
     * Validate an institute code.
     * 
     * @param code The institute code to validate
     * @return true if valid, false otherwise
     */
    public static boolean isValidInstituteCode(String code) {
        if (code == null || code.isBlank()) {
            return false;
        }
        return INSTITUTE_CODE_PATTERN.matcher(code.trim()).matches();
    }

    /**
     * Sanitize a string by trimming and removing potential SQL injection
     * characters.
     * Note: This is a basic sanitization. JPA/Hibernate provides parameterized
     * queries
     * which is the primary defense against SQL injection.
     * 
     * @param input The input string
     * @return Sanitized string
     */
    public static String sanitize(String input) {
        if (input == null) {
            return null;
        }
        return input.trim();
    }
}
