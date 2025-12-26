# ADR-001: Nimbus JOSE+JWT as Primary JWT Library

## Status

**Accepted**

**Date**: 2025-12-26

## Context

The Spring Security Template requires a robust, enterprise-grade JWT library to handle:
- Token generation (access tokens and refresh tokens)
- Cryptographic signing (RSA, HMAC, ECDSA)
- Token validation and parsing
- Support for advanced JOSE (JSON Object Signing and Encryption) standards
- Future extensibility for OAuth2/OIDC integration

The library must meet the requirements of:
- **Banking and fintech environments** (high security standards)
- **OWASP ASVS Level 2/3** compliance
- **Regulatory frameworks**: ENS (Esquema Nacional de Seguridad), ISO 27001
- **Production readiness**: battle-tested, actively maintained
- **Flexibility**: support for multiple algorithms and key management strategies

## Decision

We will use **Nimbus JOSE+JWT** (`com.nimbusds:nimbus-jose-jwt`) as the primary JWT library for this template.

### Reasoning

1. **Complete JOSE compliance**: Nimbus implements all JOSE specifications:
   - RFC 7515 (JWS - JSON Web Signature)
   - RFC 7516 (JWE - JSON Web Encryption)
   - RFC 7517 (JWK - JSON Web Key)
   - RFC 7518 (JWA - JSON Web Algorithms)
   - RFC 7519 (JWT - JSON Web Token)

2. **Enterprise adoption**: Used by major institutions:
   - Banks and financial services
   - Government systems
   - Spring Security OAuth2 and Spring Authorization Server
   - Keycloak (Red Hat's identity provider)

3. **Algorithm flexibility**: Supports RSA, ECDSA, HMAC, and future algorithms without breaking changes.

4. **JWE support**: Allows token encryption (not just signing), critical for sensitive claims.

5. **Extensibility**: Clean API for custom validators, claim processors, and key providers.

6. **Active maintenance**: Regular security updates and RFC compliance.

## Alternatives Considered

### Alternative 1: JJWT (Java JWT by Okta/jwks-rsa-java)

**Pros**:
- ✅ Simpler API, easier learning curve
- ✅ Good for small projects or prototypes
- ✅ Fluent builder pattern
- ✅ Smaller dependency footprint

**Cons**:
- ❌ **No JWE support** (encryption)
- ❌ **Limited JOSE compliance** (only JWS and JWT)
- ❌ Less extensible for OAuth2/OIDC integrations
- ❌ Not used by Spring Security's own OAuth2 implementation
- ❌ Smaller community in enterprise contexts

**Why rejected**: While JJWT is sufficient for simple use cases, this template targets **enterprise and regulated environments** where full JOSE compliance and JWE support are valuable. The lack of encryption capabilities and limited OAuth2 compatibility make it unsuitable for future-proofing.

### Alternative 2: Auth0 Java JWT

**Pros**:
- ✅ Good documentation
- ✅ Auth0 ecosystem integration

**Cons**:
- ❌ Vendor-specific (Auth0-centric design)
- ❌ Less flexible for non-Auth0 workflows
- ❌ Limited JWE support
- ❌ Smaller adoption outside Auth0 users

**Why rejected**: Introduces vendor coupling. This template is designed to be **vendor-agnostic**.

### Alternative 3: jose4j

**Pros**:
- ✅ Full JOSE compliance
- ✅ Well-tested

**Cons**:
- ❌ Smaller community compared to Nimbus
- ❌ Not used by Spring Security ecosystem
- ❌ Less documentation and examples

**Why rejected**: Nimbus has broader adoption and better integration with Spring Security.

## Consequences

### Positive

- ✅ **Future-proof**: Supports encryption (JWE) for sensitive claims if needed
- ✅ **Standards-compliant**: Full JOSE/JWT adherence
- ✅ **Enterprise-ready**: Proven in banking and government sectors
- ✅ **Spring Security alignment**: Same library used by Spring Authorization Server
- ✅ **Algorithm agility**: Easy to switch from RSA to ECDSA or other algorithms
- ✅ **OAuth2/OIDC ready**: Natural path to integrate OpenID Connect in the future

### Negative

- ⚠️ **Steeper learning curve**: More verbose API compared to JJWT
- ⚠️ **Larger dependency**: More classes and interfaces
- ⚠️ **Requires more boilerplate**: Manual construction of JWS/JWE objects

### Neutral

- ℹ️ API is more explicit and type-safe, reducing runtime errors
- ℹ️ Encourages proper abstraction (e.g., `TokenProvider` interface in application layer)

## Implementation Notes

### Dependency

```xml
<dependency>
    <groupId>com.nimbusds</groupId>
    <artifactId>nimbus-jose-jwt</artifactId>
    <version>9.40</version>
</dependency>
```

### Key Classes

- **`JWSSigner`**: Signs tokens with RSA/HMAC/ECDSA
- **`JWSVerifier`**: Validates token signatures
- **`JWTClaimsSet`**: Represents JWT claims (subject, expiration, custom claims)
- **`SignedJWT`**: Immutable representation of a signed JWT

### Code Location

- **Primary implementation**: `infrastructure/jwt/nimbus/NimbusJwtTokenProvider.java`
- **Abstraction**: `application/auth/port/out/TokenProvider.java`
- **Key management**: `infrastructure/jwt/key/` (RSA key providers)

### Example Usage

```java
// Generate Access Token
JWTClaimsSet claims = new JWTClaimsSet.Builder()
    .subject(userId)
    .issueTime(Date.from(now))
    .expirationTime(Date.from(expiry))
    .claim("roles", roles)
    .claim("scopes", scopes)
    .build();

SignedJWT signedJWT = new SignedJWT(
    new JWSHeader.Builder(JWSAlgorithm.RS256).keyID(keyId).build(),
    claims
);
signedJWT.sign(jwsSigner);
return signedJWT.serialize();
```

## References

- [Nimbus JOSE+JWT Documentation](https://connect2id.com/products/nimbus-jose-jwt)
- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [RFC 7515 - JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
- [RFC 7516 - JSON Web Encryption (JWE)](https://datatracker.ietf.org/doc/html/rfc7516)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Spring Authorization Server (uses Nimbus)](https://github.com/spring-projects/spring-authorization-server)

## Review

**Reviewers**: Security Team, Platform Architecture
**Approved by**: Technical Lead
**Review date**: 2025-12-26
