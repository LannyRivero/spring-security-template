package com.lanny.spring_security_template.infrastructure.web.common.exception;

import com.lanny.spring_security_template.infrastructure.web.common.dto.ErrorResponse;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

/**
 * Global exception handler for REST controllers.
 *
 * <p>This handler catches exceptions thrown by controllers and converts them to
 * standardized {@link ErrorResponse} objects following RFC 9457 Problem Details format.
 *
 * <p>Handles:
 * <ul>
 *   <li>Validation errors (400 Bad Request)</li>
 *   <li>Authentication errors (401 Unauthorized)</li>
 *   <li>Authorization errors (403 Forbidden)</li>
 *   <li>Generic exceptions (500 Internal Server Error)</li>
 * </ul>
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /**
     * Handles validation errors from @Valid annotations.
     *
     * @param ex      the validation exception
     * @param request the HTTP request
     * @return error response with field-specific validation errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationErrors(
        MethodArgumentNotValidException ex,
        HttpServletRequest request
    ) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ErrorResponse response = ErrorResponse.badRequest(
            "Validation failed for one or more fields. Check the 'errors' field for details.",
            request.getRequestURI(),
            errors
        );

        log.warn("Validation error on {}: {}", request.getRequestURI(), errors);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }

    /**
     * Handles authentication errors (invalid credentials).
     *
     * @param ex      the authentication exception
     * @param request the HTTP request
     * @return 401 Unauthorized error response
     */
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCredentials(
        BadCredentialsException ex,
        HttpServletRequest request
    ) {
        ErrorResponse response = ErrorResponse.unauthorized(
            "Invalid username/email or password",
            request.getRequestURI()
        );

        log.warn("Authentication failed on {}: {}", request.getRequestURI(), ex.getMessage());

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
    }

    /**
     * Handles authorization errors (insufficient permissions).
     *
     * @param ex      the authorization exception
     * @param request the HTTP request
     * @return 403 Forbidden error response
     */
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDenied(
        AccessDeniedException ex,
        HttpServletRequest request
    ) {
        ErrorResponse response = ErrorResponse.forbidden(
            "Insufficient permissions. Required scope missing from JWT token.",
            request.getRequestURI()
        );

        log.warn("Access denied on {}: {}", request.getRequestURI(), ex.getMessage());

        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
    }

    /**
     * Handles all other unhandled exceptions.
     *
     * @param ex      the exception
     * @param request the HTTP request
     * @return 500 Internal Server Error response
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGenericException(
        Exception ex,
        HttpServletRequest request
    ) {
        ErrorResponse response = ErrorResponse.internalServerError(
            "An unexpected error occurred. Please contact support if the issue persists.",
            request.getRequestURI()
        );

        log.error("Unexpected error on {}: {}", request.getRequestURI(), ex.getMessage(), ex);

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }

    /**
     * Handles illegal argument exceptions (400 Bad Request).
     *
     * @param ex      the exception
     * @param request the HTTP request
     * @return 400 Bad Request error response
     */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegalArgument(
        IllegalArgumentException ex,
        HttpServletRequest request
    ) {
        ErrorResponse response = ErrorResponse.badRequest(
            ex.getMessage(),
            request.getRequestURI()
        );

        log.warn("Invalid argument on {}: {}", request.getRequestURI(), ex.getMessage());

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
    }
}
