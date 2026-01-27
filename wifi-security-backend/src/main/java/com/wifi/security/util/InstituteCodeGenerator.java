package com.wifi.security.util;

import com.wifi.security.enums.InstituteType;
import com.wifi.security.repository.InstituteRepository;
import org.springframework.stereotype.Component;

import java.security.SecureRandom;
import java.time.Year;

/**
 * Utility class for generating unique institute codes.
 * Pattern: [PREFIX][YEAR][RANDOM]
 * Example: KASC2026A1B2
 */
@Component
public class InstituteCodeGenerator {

    private static final String ALPHANUMERIC = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int RANDOM_SUFFIX_LENGTH = 4;

    private final InstituteRepository instituteRepository;

    public InstituteCodeGenerator(InstituteRepository instituteRepository) {
        this.instituteRepository = instituteRepository;
    }

    /**
     * Generate a unique institute code based on the institute name and type.
     * 
     * @param instituteName The name of the institute
     * @param type          The type of institute
     * @return A unique institute code
     */
    public String generate(String instituteName, InstituteType type) {
        String code;
        int attempts = 0;
        int maxAttempts = 100;

        do {
            code = generateCode(instituteName);
            attempts++;

            if (attempts >= maxAttempts) {
                throw new RuntimeException(
                        "Failed to generate unique institute code after " + maxAttempts + " attempts");
            }
        } while (instituteRepository.existsByInstituteCode(code));

        return code;
    }

    private String generateCode(String instituteName) {
        // Get prefix from institute name (first 4 letters, uppercase)
        String prefix = getPrefix(instituteName);

        // Get current year
        String year = String.valueOf(Year.now().getValue());

        // Generate random suffix
        String randomSuffix = generateRandomSuffix();

        return prefix + year + randomSuffix;
    }

    private String getPrefix(String instituteName) {
        // Remove special characters and spaces, take first 4 letters
        String cleaned = instituteName.replaceAll("[^a-zA-Z]", "").toUpperCase();

        if (cleaned.length() >= 4) {
            return cleaned.substring(0, 4);
        } else if (cleaned.length() > 0) {
            // Pad with random letters if name is too short
            StringBuilder padded = new StringBuilder(cleaned);
            while (padded.length() < 4) {
                padded.append(ALPHANUMERIC.charAt(RANDOM.nextInt(26))); // Only letters for padding
            }
            return padded.toString();
        } else {
            // Generate random prefix if no valid characters
            StringBuilder randomPrefix = new StringBuilder();
            for (int i = 0; i < 4; i++) {
                randomPrefix.append(ALPHANUMERIC.charAt(RANDOM.nextInt(26)));
            }
            return randomPrefix.toString();
        }
    }

    private String generateRandomSuffix() {
        StringBuilder suffix = new StringBuilder();
        for (int i = 0; i < RANDOM_SUFFIX_LENGTH; i++) {
            suffix.append(ALPHANUMERIC.charAt(RANDOM.nextInt(ALPHANUMERIC.length())));
        }
        return suffix.toString();
    }
}
