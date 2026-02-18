package com.wifi.security.exception;

/**
 * Exception thrown when the circuit breaker is open due to repeated failures.
 * Prevents cascading failures when downstream services are unavailable.
 */
public class CircuitBreakerOpenException extends RuntimeException {

    private final String serviceName;
    private final long retryAfterMs;

    public CircuitBreakerOpenException(String serviceName) {
        super(String.format("Circuit breaker open for service: %s", serviceName));
        this.serviceName = serviceName;
        this.retryAfterMs = 30000; // Default 30 seconds
    }

    public CircuitBreakerOpenException(String serviceName, long retryAfterMs) {
        super(String.format("Circuit breaker open for service: %s. Retry after %dms", serviceName, retryAfterMs));
        this.serviceName = serviceName;
        this.retryAfterMs = retryAfterMs;
    }

    public String getServiceName() {
        return serviceName;
    }

    public long getRetryAfterMs() {
        return retryAfterMs;
    }
}
