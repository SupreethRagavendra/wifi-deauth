package com.wifi.security.exception;

import com.wifi.security.dto.response.ApiErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.dao.DataIntegrityViolationException;
import org.hibernate.exception.ConstraintViolationException;

import com.wifi.security.exception.DetectionTimeoutException;
import com.wifi.security.exception.DetectionServiceException;
import com.wifi.security.exception.CircuitBreakerOpenException;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

/**
 * Global exception handler for the application.
 * Provides consistent error responses across all controllers.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

        private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

        @ExceptionHandler(DuplicateEmailException.class)
        public ResponseEntity<ApiErrorResponse> handleDuplicateEmail(
                        DuplicateEmailException ex, HttpServletRequest request) {
                logger.warn("Duplicate email registration attempt: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Conflict")
                                .message(ex.getMessage())
                                .status(HttpStatus.CONFLICT.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }

        @ExceptionHandler(InvalidInstituteCodeException.class)
        public ResponseEntity<ApiErrorResponse> handleInvalidInstituteCode(
                        InvalidInstituteCodeException ex, HttpServletRequest request) {
                logger.warn("Invalid institute code: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Not Found")
                                .message(ex.getMessage())
                                .status(HttpStatus.NOT_FOUND.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }

        @ExceptionHandler(InvalidCredentialsException.class)
        public ResponseEntity<ApiErrorResponse> handleInvalidCredentials(
                        InvalidCredentialsException ex, HttpServletRequest request) {
                logger.warn("Invalid login attempt: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Unauthorized")
                                .message(ex.getMessage())
                                .status(HttpStatus.UNAUTHORIZED.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        @ExceptionHandler(UnauthorizedException.class)
        public ResponseEntity<ApiErrorResponse> handleUnauthorized(
                        UnauthorizedException ex, HttpServletRequest request) {
                logger.warn("Unauthorized access attempt: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Forbidden")
                                .message(ex.getMessage())
                                .status(HttpStatus.FORBIDDEN.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        }

        @ExceptionHandler(ResourceNotFoundException.class)
        public ResponseEntity<ApiErrorResponse> handleResourceNotFound(
                        ResourceNotFoundException ex, HttpServletRequest request) {
                logger.warn("Resource not found: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Not Found")
                                .message(ex.getMessage())
                                .status(HttpStatus.NOT_FOUND.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
        }

        @ExceptionHandler(MethodArgumentNotValidException.class)
        public ResponseEntity<Map<String, Object>> handleValidationExceptions(
                        MethodArgumentNotValidException ex, HttpServletRequest request) {
                logger.warn("Validation error: {}", ex.getMessage());

                Map<String, String> errors = new HashMap<>();
                ex.getBindingResult().getAllErrors().forEach((error) -> {
                        String fieldName = ((FieldError) error).getField();
                        String errorMessage = error.getDefaultMessage();
                        errors.put(fieldName, errorMessage);
                });

                Map<String, Object> response = new HashMap<>();
                response.put("error", "Validation Failed");
                response.put("message", "One or more fields have validation errors");
                response.put("status", HttpStatus.BAD_REQUEST.value());
                response.put("timestamp", LocalDateTime.now().toString());
                response.put("path", request.getRequestURI());
                response.put("fieldErrors", errors);

                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        @ExceptionHandler({ HttpMessageNotReadableException.class, MethodArgumentTypeMismatchException.class })
        public ResponseEntity<ApiErrorResponse> handleBadRequest(
                        Exception ex, HttpServletRequest request) {
                logger.warn("Bad request: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Bad Request")
                                .message("Invalid request body or parameters")
                                .status(HttpStatus.BAD_REQUEST.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
        }

        @ExceptionHandler(BadCredentialsException.class)
        public ResponseEntity<ApiErrorResponse> handleBadCredentials(
                        BadCredentialsException ex, HttpServletRequest request) {
                logger.warn("Bad credentials: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Unauthorized")
                                .message("Invalid email or password")
                                .status(HttpStatus.UNAUTHORIZED.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        @ExceptionHandler(AuthenticationException.class)
        public ResponseEntity<ApiErrorResponse> handleAuthentication(
                        AuthenticationException ex, HttpServletRequest request) {
                logger.warn("Authentication error: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Unauthorized")
                                .message("Authentication failed")
                                .status(HttpStatus.UNAUTHORIZED.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
        }

        @ExceptionHandler(AccessDeniedException.class)
        public ResponseEntity<ApiErrorResponse> handleAccessDenied(
                        AccessDeniedException ex, HttpServletRequest request) {
                logger.warn("Access denied: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Forbidden")
                                .message("Access denied")
                                .status(HttpStatus.FORBIDDEN.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
        }

        @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
        public ResponseEntity<ApiErrorResponse> handleMethodNotSupported(
                        HttpRequestMethodNotSupportedException ex, HttpServletRequest request) {
                logger.warn("Method not supported: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Method Not Allowed")
                                .message(ex.getMessage())
                                .status(HttpStatus.METHOD_NOT_ALLOWED.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.METHOD_NOT_ALLOWED).body(response);
        }

        @ExceptionHandler(DataIntegrityViolationException.class)
        public ResponseEntity<ApiErrorResponse> handleDataIntegrityViolation(
                        DataIntegrityViolationException ex, HttpServletRequest request) {
                logger.warn("Data integrity violation (likely duplicate email during concurrent request): {}",
                                ex.getMostSpecificCause().getMessage());

                String message = "A conflict occurred. This usually means a duplicate entry was attempted.";
                if (ex.getMostSpecificCause().getMessage().contains("email")) {
                        message = "Email already registered. Please use a different email.";
                }

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Conflict")
                                .message(message)
                                .status(HttpStatus.CONFLICT.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }

        @ExceptionHandler(ConstraintViolationException.class)
        public ResponseEntity<ApiErrorResponse> handleConstraintViolation(
                        ConstraintViolationException ex, HttpServletRequest request) {
                logger.warn("Constraint violation (concurrent access): {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Conflict")
                                .message("A database constraint was violated. This usually means duplicate data.")
                                .status(HttpStatus.CONFLICT.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.CONFLICT).body(response);
        }

        @ExceptionHandler(DetectionTimeoutException.class)
        public ResponseEntity<ApiErrorResponse> handleDetectionTimeout(
                        DetectionTimeoutException ex, HttpServletRequest request) {
                logger.warn("Detection analysis timeout: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Gateway Timeout")
                                .message("Detection analysis timed out. Partial results may be available.")
                                .status(HttpStatus.GATEWAY_TIMEOUT.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.GATEWAY_TIMEOUT).body(response);
        }

        @ExceptionHandler(DetectionServiceException.class)
        public ResponseEntity<ApiErrorResponse> handleDetectionServiceException(
                        DetectionServiceException ex, HttpServletRequest request) {
                logger.error("Detection service error: {}", ex.getMessage(), ex);

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Service Error")
                                .message("Detection analysis failed. Please try again.")
                                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }

        @ExceptionHandler(CircuitBreakerOpenException.class)
        public ResponseEntity<ApiErrorResponse> handleCircuitBreakerOpen(
                        CircuitBreakerOpenException ex, HttpServletRequest request) {
                logger.warn("Circuit breaker open: {}", ex.getMessage());

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Service Unavailable")
                                .message("Detection service temporarily unavailable. Please retry after " +
                                                (ex.getRetryAfterMs() / 1000) + " seconds.")
                                .status(HttpStatus.SERVICE_UNAVAILABLE.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                                .header("Retry-After", String.valueOf(ex.getRetryAfterMs() / 1000))
                                .body(response);
        }

        @ExceptionHandler(Exception.class)
        public ResponseEntity<ApiErrorResponse> handleGenericException(
                        Exception ex, HttpServletRequest request) {
                logger.error("Unexpected error occurred: {}", ex.getMessage(), ex);

                ApiErrorResponse response = ApiErrorResponse.builder()
                                .error("Internal Server Error")
                                .message("An unexpected error occurred. Please try again later.")
                                .status(HttpStatus.INTERNAL_SERVER_ERROR.value())
                                .timestamp(LocalDateTime.now())
                                .path(request.getRequestURI())
                                .build();

                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
        }
}
