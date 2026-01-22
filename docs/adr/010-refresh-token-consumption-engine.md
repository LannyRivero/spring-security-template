# ADR-010: Refresh Token Consumption Engine (Single Source of Truth)

## Status

**Proposed**

**Date**: 2026-01-19

## Context

Refresh token consumption is a security-critical capability. It must guarantee **replay protection** (reuse detection) and provide **incident-grade observability**.

Current implementation has good building blocks but responsibilities are distributed across:
- a Redis consumer (atomic consume logic),
- an infrastructure adapter,
- production guards / startup checks,
- metrics emitted in multiple places,
- and implicit Redis scripts / prefixes.

This creates operational and security risks:

- **Double accounting**: metrics and logs may disagree about whether a token was consumed, revoked, reused, or expired.
- **Divergent prefixes**: different components may build Redis keys differently, causing false negatives during reuse detection.
- **Incident ambiguity**: during an attack (token replay / leakage), it is hard to determine the exact outcome of a refresh request.
- **Inconsistent semantics**: a boolean consumption result loses important information (reused vs revoked vs expired).

Constraints / requirements:
- Refresh token consumption must be **atomic** and **replay-safe**.
- The system must provide **stable, low-cardinality metrics** for monitoring and alerts.
- Redis key strategy and scripts must be **centralized** and **consistent**.
- The solution must be compatible with the current architecture (Clean/Hexagonal boundaries).
- JWT failures must not produce 500 responses due to infrastructure inconsistencies.

## Decision

We will implement a **Refresh Token Consumption Engine** as the **single source of truth** for:

- atomic token consumption,
- semantic results (consumed / reused / revoked / expired),
- Redis key/prefix strategy,
- metrics emission for consumption outcomes,
- and script execution.

All other components (adapters, services, guards) will **delegate** to the engine and must not re-implement consumption semantics.

We will replace boolean-only outcomes with a semantic result:
- `CONSUMED`
- `REUSED`
- `REVOKED`
- `EXPIRED`

### Reasoning

- **Reason 1**: A single engine prevents divergent behavior across adapters, scripts, and metrics.
- **Reason 2**: Semantic results enable incident-grade diagnosis and meaningful Prometheus alerts.
- **Reason 3**: Centralized Redis key strategy eliminates prefix drift and replay false negatives.

## Alternatives Considered

### Alternative 1: Keep current split responsibilities + improve documentation

**Pros**:
- Minimal code changes
- No interface changes

**Cons**:
- Still allows key prefix drift
- Metrics/logs can remain inconsistent
- Hard to support reliable replay-attack alerting

**Why rejected**: The risks are systemic and remain present even with better docs.

### Alternative 2: Let each layer emit its own metrics (adapter + consumer + guards)

**Pros**:
- Local visibility per component
- Easy incremental adoption

**Cons**:
- Double accounting is likely
- Metrics are not a single truth
- Incident reconstruction becomes unreliable

**Why rejected**: Security observability must be coherent and deterministic.

## Consequences

### Positive

- ✅ Single source of truth for refresh token consumption
- ✅ Replay attacks become observable (`REUSED` outcome)
- ✅ Stable Prometheus metrics with controlled cardinality
- ✅ Redis key strategy becomes consistent and enforceable
- ✅ Easier incident response and root cause analysis

### Negative

- ⚠️ Requires refactor and possibly a port signature change (boolean → semantic result)
- ⚠️ Needs careful migration to avoid breaking existing tests

### Neutral

- ℹ️ Redis remains the required dependency in prod-like environments
- ℹ️ No impact on domain/application boundaries (engine remains infrastructure)

## Implementation Notes

Key elements:
- `RedisRefreshTokenConsumptionEngine` executes a single Lua script.
- `RefreshTokenRedisKeys` centralizes all Redis key prefixes.
- Metrics emitted only from the engine:
  - `auth_refresh_consumption_total{result="CONSUMED|REUSED|REVOKED|EXPIRED"}`
  - optional latency timer.

Example mapping (migration phase):

```java
// Migration stage: keep boolean port temporarily
boolean allowed = (engine.consume(jti, ttl) == RefreshTokenConsumptionResult.CONSUMED);

References

RFC 6749 - OAuth 2.0 (Refresh Tokens)

OWASP Session Management Cheat Sheet

OWASP JSON Web Token Cheat Sheet

Redis Lua Scripting

Review

Reviewers: Backend Chapter, Security Reviewer
Approved by: TBD
Review date: TBD