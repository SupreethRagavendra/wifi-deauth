package com.wifi.security.exception;

/**
 * Exception thrown when Layer 1 detection analysis times out.
 * This typically occurs when database queries or individual analyzers
 * exceed the configured timeout threshold.
 */
public class DetectionTimeoutException extends RuntimeException {

    private final String sourceMac;
    private final long timeoutMs;
    private final int partialScore;

    public DetectionTimeoutException(String message) {
        super(message);
        this.sourceMac = null;
        this.timeoutMs = 0;
        this.partialScore = 0;
    }

    public DetectionTimeoutException(String message, Throwable cause) {
        super(message, cause);
        this.sourceMac = null;
        this.timeoutMs = 0;
        this.partialScore = 0;
    }

    public DetectionTimeoutException(String sourceMac, long timeoutMs, int partialScore) {
        super(String.format("Detection timeout for source %s after %dms (partial score: %d)",
                sourceMac, timeoutMs, partialScore));
        this.sourceMac = sourceMac;
        this.timeoutMs = timeoutMs;
        this.partialScore = partialScore;
    }

    public String getSourceMac() {
        return sourceMac;
    }

    public long getTimeoutMs() {
        return timeoutMs;
    }

    public int getPartialScore() {
        return partialScore;
    }
}
