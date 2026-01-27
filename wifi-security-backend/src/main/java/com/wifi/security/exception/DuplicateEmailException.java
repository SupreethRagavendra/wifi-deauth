package com.wifi.security.exception;

/**
 * Exception thrown when attempting to register with an email that already
 * exists.
 */
public class DuplicateEmailException extends RuntimeException {

    public DuplicateEmailException(String message) {
        super(message);
    }

    public DuplicateEmailException(String email, Throwable cause) {
        super("Email already registered: " + email, cause);
    }
}
