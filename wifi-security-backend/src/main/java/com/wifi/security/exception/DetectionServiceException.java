package com.wifi.security.exception;

/**
 * General exception for detection service failures.
 * Wraps underlying exceptions from analyzers or infrastructure.
 */
public class DetectionServiceException extends RuntimeException {

    private final String analyzerName;
    private final String sourceMac;

    public DetectionServiceException(String message) {
        super(message);
        this.analyzerName = null;
        this.sourceMac = null;
    }

    public DetectionServiceException(String message, Throwable cause) {
        super(message, cause);
        this.analyzerName = null;
        this.sourceMac = null;
    }

    public DetectionServiceException(String analyzerName, String sourceMac, String message, Throwable cause) {
        super(String.format("[%s] Failed for source %s: %s", analyzerName, sourceMac, message), cause);
        this.analyzerName = analyzerName;
        this.sourceMac = sourceMac;
    }

    public String getAnalyzerName() {
        return analyzerName;
    }

    public String getSourceMac() {
        return sourceMac;
    }
}
