# ADR-004: Refresh Token Strategy with Rotation and Reuse Detection

## Status

**Accepted**

**Date**: 2025-12-26

## Context

JWT-based authentication requires two types of tokens:
- **Access Token**: Short-lived (15-60 minutes), included in every API request
- **Refresh Token**: Long-lived (7-30 days), used to obtain new access tokens

Refresh tokens introduce several security challenges:
- **Token theft**: If stolen, attacker gains persistent access
- **Token reuse**: Attacker might replay a compromised refresh token
- **Revocation**: How to invalidate tokens before expiration?
- **Family tracking**: How to detect if a token chain is compromised?

OWASP recommends **Refresh Token Rotation**: each refresh operation:
1. Invalidates the old refresh token
2. Issues a new refresh token
3. Detects and mitigates reuse attempts

We need a strategy that:
- Prevents refresh token reuse (even if stolen)
- Allows graceful revocation of entire token families
- Supports concurrent clients (mobile + web + desktop)
- Maintains audit trails for security investigations
- Balances security with operational complexity

## Decision

We will implement **Refresh Token Rotation with Family-Based Reuse Detection**.

### Core Strategy

1. **Rotation on every refresh**:
   - Client sends `refresh_token_A`
   - Server validates `token_A`
   - Server generates `refresh_token_B` (new token, same family)
   - Server revokes `token_A`
   - Server returns `token_B` + new access token

2. **Family Tracking**:
   - Each refresh token has a `familyId` (UUID)
   - All tokens in a rotation chain share the same `familyId`
   - Tokens form a linked list: `token_B.previousTokenJti = token_A.jti`

3. **Reuse Detection**:
   - If a **revoked token is reused** → attacker likely has it
   - Action: **Revoke entire token family** (all children)
   - User must re-authenticate

4. **Persistence**:
   - Store tokens in database with:
     - `jti` (unique token ID)
     - `familyId` (for grouping rotated tokens)
     - `userId` (owner)
     - `issuedAt`, `expiresAt` (lifecycle)
     - `revoked` (boolean flag)
     - `previousTokenJti` (chain tracking)

### Security Properties

| Scenario | Behavior |
|----------|----------|
| Normal refresh | ✅ Old token revoked, new token issued |
| Stolen token used once | ⚠️ Works (attacker gets 1 access token) |
| Stolen token reused | 🚨 Family revoked, user forced to re-login |
| Concurrent clients | ✅ Each client has separate token family |
| Manual logout | ✅ Revoke specific token family |
| Global logout | ✅ Revoke all families for user |

## Alternatives Considered

### Alternative 1: Stateless Refresh Tokens (No Rotation)

**Approach**: Refresh tokens are JWTs, validated cryptographically only.

**Pros**:
- ✅ No database lookups (faster)
- ✅ Simpler implementation

**Cons**:
- ❌ **No revocation**: Cannot invalidate tokens until expiration
- ❌ **No reuse detection**: Stolen tokens remain valid
- ❌ **Security risk**: If leaked, attacker has persistent access
- ❌ **OWASP violation**: Does not meet ASVS Level 2 requirements

**Why rejected**: Stateless refresh tokens are **not secure enough** for enterprise applications. Inability to revoke tokens is a critical vulnerability.

### Alternative 2: Rotation Without Reuse Detection

**Approach**: Rotate tokens but don't track families or detect reuse.

**Pros**:
- ✅ Limits damage (old tokens invalidated)
- ✅ Simpler than family tracking

**Cons**:
- ❌ **Silent compromise**: Attacker can use stolen token until rotation
- ❌ **No breach detection**: Cannot identify if tokens are compromised
- ❌ **Delayed response**: No automatic mitigation

**Why rejected**: Without reuse detection, we cannot identify breaches. **Proactive security** (detect and respond) is superior to reactive (just rotate).

### Alternative 3: Sliding Sessions (No Rotation)

**Approach**: Refresh token lifetime extends on each use.

**Pros**:
- ✅ User convenience (no re-authentication if active)
- ✅ Simpler (no token families)

**Cons**:
- ❌ **Indefinite sessions**: Active users never re-authenticate
- ❌ **Compliance issues**: Violates policies requiring periodic re-auth (PCI-DSS)
- ❌ **Revocation complexity**: Hard to force re-authentication

**Why rejected**: Indefinite sessions are a **security anti-pattern** in regulated environments.

### Alternative 4: One-Time Refresh Tokens (No Families)

**Approach**: Each refresh token can only be used once, no family tracking.

**Pros**:
- ✅ Strong security (one-time use)
- ✅ Simpler model

**Cons**:
- ❌ **Concurrent client issues**: Mobile + Web clients interfere with each other
- ❌ **Race conditions**: Simultaneous refresh requests can break flow
- ❌ **Poor UX**: Users logged out unexpectedly

**Why rejected**: **Multiple concurrent devices** are a common use case (phone + laptop). One-time tokens don't support this well without complex orchestration.

## Consequences

### Positive

- ✅ **OWASP compliant**: Meets ASVS Level 2/3 requirements
- ✅ **Breach detection**: Automatically identifies compromised tokens
- ✅ **Automatic mitigation**: Revokes all tokens in a compromised family
- ✅ **Audit trail**: Database tracks token usage and revocations
- ✅ **Granular control**: Revoke single family or all families per user
- ✅ **Concurrent clients**: Each device has independent token family
- ✅ **Compliance-ready**: Meets PCI-DSS, ENS, ISO 27001 token requirements

### Negative

- ⚠️ **Database dependency**: Requires persistence for token tracking
- ⚠️ **Performance overhead**: Database lookup on every refresh
- ⚠️ **Complexity**: Family tracking and reuse detection logic
- ⚠️ **Clock skew issues**: Concurrent refreshes from same client can cause false positives

### Neutral

- ℹ️ Cleanup job required to purge expired tokens (scheduled task)
- ℹ️ User experience: If token stolen and reused, legitimate user must re-login

## Implementation Notes

### Database Schema

```sql
CREATE TABLE refresh_tokens (
    id BIGSERIAL PRIMARY KEY,
    jti VARCHAR(255) UNIQUE NOT NULL,           -- JWT ID (unique token identifier)
    family_id VARCHAR(255) NOT NULL,            -- Groups rotated tokens
    user_id VARCHAR(255) NOT NULL,              -- Token owner
    issued_at TIMESTAMP NOT NULL,               -- Creation time
    expires_at TIMESTAMP NOT NULL,              -- Expiration time
    revoked BOOLEAN DEFAULT FALSE,              -- Revocation flag
    previous_token_jti VARCHAR(255),            -- Chain tracking (nullable)
    token_hash VARCHAR(255) NOT NULL,           -- SHA-256 hash of token (optional security)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_jti (jti),
    INDEX idx_family_id (family_id),
    INDEX idx_user_id (user_id),
    INDEX idx_expires_at (expires_at)
);
```

### Domain Model

```java
public class RefreshToken {
    private final String jti;
    private final String familyId;
    private final String userId;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private boolean revoked;
    private final String previousTokenJti;
    
    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }
    
    public void revoke() {
        this.revoked = true;
    }
}
```

### Outbound Port (Gateway)

```java
public interface RefreshTokenStore {
    void save(RefreshToken token);
    Optional<RefreshToken> findByJti(String jti);
    void revoke(String jti);
    void revokeFamily(String familyId);  // Revoke entire family
    void revokeAllForUser(String userId); // Global logout
    List<RefreshToken> findByFamilyId(String familyId);
    void deleteExpiredTokens(Instant before); // Cleanup
}
```

### Use Case Logic (Refresh Flow)

```java
@Override
public JwtResult refresh(RefreshCommand command) {
    // 1. Parse and validate token structure
    JwtClaimsDTO claims = tokenProvider.parseToken(command.refreshToken());
    String jti = claims.jti();
    
    // 2. Lookup token in database
    RefreshToken storedToken = refreshTokenStore.findByJti(jti)
        .orElseThrow(() -> new InvalidRefreshTokenException("Token not found"));
    
    // 3. Check if token is revoked
    if (storedToken.isRevoked()) {
        // ⚠️ REUSE DETECTED — Revoke entire family
        refreshTokenStore.revokeFamily(storedToken.getFamilyId());
        auditPublisher.publish(new RefreshTokenReuseDetectedEvent(
            storedToken.getUserId(),
            storedToken.getFamilyId()
        ));
        throw new RefreshTokenReusedException("Token family revoked due to reuse");
    }
    
    // 4. Check expiration
    if (storedToken.isExpired(clock.now())) {
        throw new InvalidRefreshTokenException("Token expired");
    }
    
    // 5. Revoke current token
    refreshTokenStore.revoke(jti);
    
    // 6. Generate new tokens (same family)
    String newAccessToken = tokenProvider.generateAccessToken(/* ... */);
    String newRefreshToken = tokenProvider.generateRefreshToken(
        storedToken.getUserId(),
        refreshTokenPolicy.getTtl()
    );
    
    // 7. Store new refresh token (linked to previous)
    JwtClaimsDTO newClaims = tokenProvider.parseToken(newRefreshToken);
    RefreshToken newToken = RefreshToken.create(
        newClaims.jti(),
        storedToken.getFamilyId(), // ✅ Same family
        storedToken.getUserId(),
        clock.now(),
        newClaims.expiresAt(),
        jti // ✅ Chain tracking
    );
    refreshTokenStore.save(newToken);
    
    // 8. Return tokens
    return new JwtResult(newAccessToken, newRefreshToken, /* ... */);
}
```

### Cleanup Job

```java
@Scheduled(cron = "0 0 2 * * ?") // Daily at 2 AM
public void cleanupExpiredTokens() {
    Instant cutoff = clock.now().minus(Duration.ofDays(7));
    refreshTokenStore.deleteExpiredTokens(cutoff);
}
```

### Code Locations

- **Domain model**: `domain/model/RefreshToken.java` (if separate from User aggregate)
- **Outbound port**: `application/auth/port/out/RefreshTokenStore.java`
- **JPA adapter**: `infrastructure/persistence/jpa/RefreshTokenStoreJpa.java`
- **Use case**: `application/auth/service/AuthUseCaseImpl.java#refresh()`
- **Validator**: `application/auth/service/RefreshTokenValidator.java`
- **Cleanup**: `infrastructure/scheduler/RefreshTokenCleanupScheduler.java`

## Testing Strategy

### Unit Tests

```java
@Test
void shouldRevokeEntireFamilyWhenRevokedTokenIsReused() {
    // Given: Token already revoked
    RefreshToken revokedToken = RefreshToken.create(/* ... */).revoke();
    when(refreshTokenStore.findByJti(jti)).thenReturn(Optional.of(revokedToken));
    
    // When: Attempting to reuse
    assertThatThrownBy(() -> authUseCase.refresh(command))
        .isInstanceOf(RefreshTokenReusedException.class);
    
    // Then: Entire family revoked
    verify(refreshTokenStore).revokeFamily(revokedToken.getFamilyId());
    verify(auditPublisher).publish(any(RefreshTokenReuseDetectedEvent.class));
}
```

### Integration Tests

```java
@SpringBootTest
@Transactional
class RefreshTokenRotationIntegrationTest {
    @Test
    void shouldRotateTokenSuccessfully() {
        // Given: User logged in with refresh token
        JwtResult initialTokens = authUseCase.login(loginCommand);
        
        // When: Refreshing token
        JwtResult refreshedTokens = authUseCase.refresh(
            new RefreshCommand(initialTokens.refreshToken())
        );
        
        // Then: New tokens issued, old token revoked
        assertThat(refreshedTokens.refreshToken())
            .isNotEqualTo(initialTokens.refreshToken());
        
        // And: Old token cannot be reused
        assertThatThrownBy(() -> authUseCase.refresh(
            new RefreshCommand(initialTokens.refreshToken())
        )).isInstanceOf(RefreshTokenReusedException.class);
    }
}
```

## Monitoring & Alerts

### Metrics to Track

```java
// Prometheus counters
Counter.builder("auth.refresh.success").register(registry);
Counter.builder("auth.refresh.reuse_detected").register(registry);
Counter.builder("auth.refresh.expired").register(registry);
Counter.builder("auth.refresh.family_revoked").register(registry);
```

### Alert Rules

```yaml
# Alert if reuse detection spikes (potential breach)
- alert: RefreshTokenReuseSpike
  expr: rate(auth_refresh_reuse_detected[5m]) > 10
  annotations:
    summary: "Unusual refresh token reuse pattern detected"
```

## Future Enhancements

### Short-term
- ✅ Configurable grace period for clock skew (5-10 seconds)
- ✅ Device fingerprinting (store User-Agent, IP for context)

### Long-term
- 🔄 Redis caching layer for token lookups (performance)
- 🔄 Anomaly detection (ML-based pattern recognition for stolen tokens)
- 🔄 User notifications (email/SMS when family revoked)

## References

- [OWASP ASVS V3 - Session Management](https://owasp.org/www-project-application-security-verification-standard/)
- [RFC 6749 - OAuth 2.0 (Refresh Tokens)](https://datatracker.ietf.org/doc/html/rfc6749#section-1.5)
- [Auth0 - Refresh Token Rotation](https://auth0.com/docs/secure/tokens/refresh-tokens/refresh-token-rotation)
- [IETF Draft - OAuth 2.0 Security Best Practices](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics)
- [Okta - Refresh Token Reuse Detection](https://developer.okta.com/docs/guides/refresh-tokens/)

## Review

**Reviewers**: Security Team, Backend Chapter
**Approved by**: CISO, Technical Lead
**Review date**: 2025-12-26
