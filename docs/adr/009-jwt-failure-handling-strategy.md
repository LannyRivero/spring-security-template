# # ADR-009: JWT Failure Handling Strategy

## Status

**Accepted**

**Date**: 2026-01-19

---

## Context

The system uses **stateless JWT-based authentication and authorization** as part of a security-focused backend template intended for production and enterprise-grade environments.

During JWT processing, multiple failure scenarios may occur:

- Missing or malformed tokens  
- Invalid signatures or issuers  
- Expired tokens  
- Revoked tokens  
- Invalid or missing mandatory claims  
- Incorrect token type usage (refresh vs access)  
- Insufficient authorities or scopes  

Without an explicit and centralized strategy, these failures can result in:

- ❌ HTTP 500 responses instead of 401/403  
- ❌ Stack traces leaking into logs  
- ❌ Inconsistent metrics and alerts  
- ❌ Broken observability and diagnosability  
- ❌ Increased operational and security risk  

Spring Security provides default exception handling mechanisms, but **does not guarantee** that all JWT-related failures are mapped deterministically unless explicitly enforced.

### Problem to Solve

Guarantee that **all JWT authentication and authorization failures**:

- Are **classified deterministically**
- Are **mapped consistently** to:
  - **401 Unauthorized** (authentication failures)
  - **403 Forbidden** (authorization failures)
- **Never result in HTTP 500**
- Produce **stable, observable, and auditable signals**

---

## Decision

We will implement a **centralized JWT failure handling strategy** based on:

1. **Normalized failure classification**
2. **Explicit translation from failure reason to security exception**
3. **Delegation of HTTP rendering to Spring Security handlers**

This strategy decouples low-level JWT exceptions from HTTP semantics and observability concerns.

---

## Design Overview

The solution is composed of three layers:

1. **Failure Classification**  
   `JwtAuthFailureReason` defines a stable, finite taxonomy of JWT failures.

2. **Failure Translation**  
   `JwtAuthFailureTranslator` maps a normalized failure reason to:
   - `AuthenticationException` → 401
   - `AccessDeniedException` → 403

3. **HTTP Rendering**  
   Spring Security’s `AuthenticationEntryPoint` and `AccessDeniedHandler` render the final response.

---

## Reasoning

- **Reason 1**: Normalizing failures avoids coupling HTTP behavior to vendor-specific JWT exceptions.
- **Reason 2**: Centralized translation ensures no JWT failure can escape as an unhandled runtime exception.
- **Reason 3**: Stable failure reasons enable consistent logging, metrics, and auditing across environments.

---

## Alternatives Considered

### Alternative 1: Handle JWT errors directly inside filters

**Pros**:
- Simple to implement
- Fewer classes initially

**Cons**:
- ❌ Error-handling logic duplicated across filters
- ❌ Easy to miss edge cases leading to HTTP 500
- ❌ Poor testability and observability

**Why rejected**: Does not scale and introduces unacceptable risk in security-critical systems.

---

### Alternative 2: Map technical JWT exceptions directly to HTTP status codes

**Pros**:
- Minimal abstraction
- Less upfront design

**Cons**:
- ❌ Tight coupling to JWT library internals
- ❌ Changes in libraries may silently change HTTP behavior
- ❌ Metrics and alerts become unstable

**Why rejected**: Violates stability and observability principles required for production-grade security.

---

## Consequences

### Positive

- ✅ No JWT-related failure can result in HTTP 500  
- ✅ Consistent HTTP semantics across the entire system  
- ✅ Stable, normalized metrics and audit logs  
- ✅ Clear separation
- ✅ Easier testing and long-term maintainability  

### Negative

- ⚠️ Additional infrastructure classes required  
- ⚠️ Developers must follow the strategy consistently  

### Neutral

- ℹ️ Spring Security remains responsible for HTTP response rendering  
- ℹ️ The strategy is independent of the JWT provider implementation  

---

## Implementation Notes

### Key Components

- `JwtAuthFailureReason` – normalized failure taxonomy  
- `JwtAuthFailureTranslator` – failure → security exception mapping  
- `JwtAuthorizationFilter` – failure classification and delegation  
- `AuthenticationEntryPoint` – renders 401 responses  
- `AccessDeniedHandler` – renders 403 responses  

### Example: Centralized Failure Translation
```java
@Component
public final class JwtAuthFailureTranslator {

    public RuntimeException translate(
            JwtAuthFailureReason reason,
            Exception ex) {

        // Authentication failures → 401
        if (isAuthenticationFailure(reason)) {
            return new BadCredentialsException("Invalid JWT token", ex);
        }

        // Authorization failures → 403
        if (isAuthorizationFailure(reason)) {
            return new AccessDeniedException("Insufficient permissions");
        }

        // Fallback (should never reach clients as 500)
        return new AuthenticationServiceException(
                "Unexpected JWT authentication error", ex);
    }
}

## References

- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 6750 - OAuth 2.0 Bearer Token Usage](https://datatracker.ietf.org/doc/html/rfc6750)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [OWASP ASVS - Authentication](https://owasp.org/www-project-application-security-verification-standard/)
- [Spring Security - Exception Handling](https://docs.spring.io/spring-security/reference/servlet/architecture.html#servlet-security-exceptionhandling)
- [Spring Security - OAuth2 Resource Server JWT](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html)


## Review

**Reviewers**: Security Team, Backend Architecture
**Approved by**: Lead Architect
**Review date**: 2025-01-19