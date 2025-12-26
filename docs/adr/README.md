# Architecture Decision Records (ADRs)

This directory contains all Architecture Decision Records for the Spring Security Template project.

## What is an ADR?

An Architecture Decision Record (ADR) is a document that captures an important architectural decision made along with its context and consequences.

## ADR Lifecycle

- **Proposed**: Decision under discussion
- **Accepted**: Decision approved and implemented
- **Deprecated**: Decision no longer recommended
- **Superseded**: Replaced by a newer ADR

## Index of ADRs

| # | Title | Status | Date | Tags |
|---|-------|--------|------|------|
| [001](001-nimbus-jwt-library.md) | Nimbus JOSE+JWT as Primary JWT Library | ✅ Accepted | 2025-12-26 | `jwt`, `library`, `security` |
| [002](002-rsa-signature-algorithm.md) | RSA Signature Algorithm as Default for JWT | ✅ Accepted | 2025-12-26 | `jwt`, `cryptography`, `rsa` |
| [003](003-hexagonal-architecture.md) | Hexagonal Architecture with Domain-Driven Design | ✅ Accepted | 2025-12-26 | `architecture`, `ddd`, `hexagonal` |
| [004](004-refresh-token-strategy.md) | Refresh Token Strategy with Rotation and Reuse Detection | ✅ Accepted | 2025-12-26 | `security`, `jwt`, `rotation`, `owasp` |
| [005](005-cryptographic-key-management.md) | Cryptographic Key Management Strategy | ✅ Accepted | 2025-12-26 | `security`, `cryptography`, `keys`, `compliance` |
| [006](006-profile-based-configuration.md) | Profile-Based Configuration Strategy | ✅ Accepted | 2025-12-26 | `configuration`, `spring`, `profiles` |
| [007](007-redis-blacklist-sessions.md) | Redis for Token Blacklist and Session Registry | ✅ Accepted | 2025-12-26 | `redis`, `infrastructure`, `scalability` |
| [008](008-stateless-jwt-authentication.md) | Stateless JWT Authentication over Session-Based | ✅ Accepted | 2025-12-26 | `authentication`, `jwt`, `stateless` |

## ADRs by Category

### Security & Cryptography
- [ADR-001: Nimbus JOSE+JWT](001-nimbus-jwt-library.md) - Enterprise-grade JWT library
- [ADR-002: RSA Signatures](002-rsa-signature-algorithm.md) - Asymmetric cryptography for JWT
- [ADR-004: Refresh Token Rotation](004-refresh-token-strategy.md) - OWASP-compliant token management
- [ADR-005: Key Management](005-cryptographic-key-management.md) - Secure key storage and rotation
- [ADR-008: Stateless JWT](008-stateless-jwt-authentication.md) - Scalable authentication

### Architecture & Design
- [ADR-003: Hexagonal Architecture](003-hexagonal-architecture.md) - Clean architecture with DDD

### Infrastructure & Operations
- [ADR-006: Profile Strategy](006-profile-based-configuration.md) - Environment-specific configuration
- [ADR-007: Redis Usage](007-redis-blacklist-sessions.md) - Distributed state management

## How to Use ADRs

### When Creating a New ADR

1. Copy [template.md](template.md)
2. Rename to `NNN-short-title.md` (e.g., `009-oauth2-integration.md`)
3. Fill in all sections:
   - **Context**: Why is this decision needed?
   - **Decision**: What did we decide?
   - **Alternatives**: What else was considered?
   - **Consequences**: What are the impacts?
4. Submit for review
5. Update this index once accepted

### When Deprecating an ADR

1. Change status to **Deprecated** in the ADR
2. Add reason for deprecation
3. Link to superseding ADR (if applicable)
4. Update index table

### When Referencing an ADR

In code, documentation, or discussions, reference ADRs using:
- **Markdown**: `[ADR-003](docs/adr/003-hexagonal-architecture.md)`
- **Comments**: `// See ADR-004 for refresh token rotation strategy`
- **Pull Requests**: "This PR implements ADR-007 (Redis blacklist)"

## Contribution Guidelines

- **Be concise**: ADRs are decision records, not tutorials
- **Be specific**: Include code examples and configuration snippets
- **Be factual**: Document actual decisions, not aspirations
- **Be humble**: Acknowledge trade-offs and limitations
- **Be timeless**: ADRs are historical records, use past tense

## Related Documentation

- [Security Documentation](../security/) - Detailed security guides
- [Architecture Diagrams](../diagrams/) - Visual representations
- [API Documentation](../api/) - OpenAPI specifications

## Contact

For questions about ADRs, contact the Architecture Guild or Platform Team.

---

**Last Updated**: 2025-12-26  
**Total ADRs**: 8
