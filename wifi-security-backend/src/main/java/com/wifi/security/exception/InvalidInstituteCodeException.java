package com.wifi.security.exception;

/**
 * Exception thrown when an invalid institute code is provided.
 */
public class InvalidInstituteCodeException extends RuntimeException {

    public InvalidInstituteCodeException(String message) {
        super(message);
    }

    public InvalidInstituteCodeException(String code, Throwable cause) {
        super("Invalid institute code: " + code, cause);
    }
}
