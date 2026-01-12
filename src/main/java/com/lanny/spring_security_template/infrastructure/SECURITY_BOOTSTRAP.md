# Security Infrastructure Bootstrap

## Purpose

This module enforces **fail-fast, production-grade security guarantees** at application startup.

The goal is simple and non-negotiable:

> **If the security configuration is unsafe, inconsistent, or incomplete, the application must not start.**

No request should ever reach the system if core security assumptions are violated.

This is achieved through a layered bootstrap mechanism composed of **Startup Checks** and **Production Guards**.

---

## Core Concepts

### 1. StartupCheck

A **StartupCheck** validates that a security component is **internally consistent and correctly wired**.

**Characteristics:**
- Executed during application bootstrap
- Stateless and deterministic
- Does not depend on runtime traffic
- Throws immediately on invalid configuration
- Independent of Spring lifecycle side effects

**Typical responsibilities:**
- Validate required beans exist
- Validate configuration coherence
- Validate cryptographic prerequisites
- Validate security invariants

**Examples:**
- JWT configuration validity
- RSA key availability
- Role provider consistency
- Refresh token consumption wiring
- CORS configuration sanity

A StartupCheck answers the question:

> *“Is this security component internally correct and safe to operate?”*

---

### 2. ProdGuard

A **ProdGuard** enforces **hard security constraints that must never be violated in production**.

**Characteristics:**
- Active only in production-like profiles
- Explicitly blocks insecure configurations
- Rejects dangerous defaults
- Prevents accidental insecure deployments
- Fails startup immediately

**Typical responsibilities:**
- Forbid insecure algorithms
- Forbid weak key sizes
- Forbid permissive CORS policies
- Forbid fallback or no-op providers
- Forbid unsafe refresh token strategies

A ProdGuard answers the question:

> *“Even if this works technically, should this ever be allowed in production?”*

---

## Execution Order

The bootstrap process follows a strict and intentional order:

Application Startup
↓
SecurityBootstrapValidator
↓
StartupChecks (consistency & correctness)
↓
ProdGuards (production hard constraints)
↓
Application Ready


### Why this order matters

1. **StartupChecks first**
   - Detect misconfigurations
   - Detect missing dependencies
   - Detect invalid security wiring

2. **ProdGuards second**
   - Enforce environment-specific security rules
   - Prevent insecure-but-working setups from reaching production

This separation ensures clarity between:
- *“This is broken”*
- *“This is dangerous”*

---

## What Causes Startup Failure

The application **will not start** if any of the following occur:

### StartupCheck failures
- Missing or invalid JWT configuration
- RSA keys not present or invalid
- Role provider inconsistencies
- Refresh token consumption misconfiguration
- Invalid CORS rules
- Network security misconfiguration

### ProdGuard failures (production profiles only)
- Weak cryptographic algorithms
- Unsafe key sizes
- Overly permissive CORS (`*`)
- No-op or insecure providers
- Unsafe refresh token strategies
- Any configuration explicitly forbidden in production

There are **no silent fallbacks**.

---

## Design Principles

This bootstrap design is built on the following principles:

- **Fail-fast over fail-late**
- **Explicit security over convenience**
- **No silent defaults**
- **Stateless and testable**
- **Infrastructure-only responsibility**
- **Clear separation of correctness vs policy**

Security misconfiguration is treated as a **deployment error**, not a runtime error.

---

## Why This Exists

Most security incidents do not happen because of complex exploits.  
They happen because:

- Security checks are scattered
- Defaults are assumed safe
- Systems start “optimistically”
- Errors appear only under traffic

This bootstrap layer exists to ensure that:

> **An insecure system never reaches runtime.**

---

## Summary

- **StartupChecks** validate correctness and consistency
- **ProdGuards** enforce non-negotiable production security rules
- **SecurityBootstrapValidator** orchestrates both
- Any violation aborts startup immediately

This is an intentional, defensive design suitable for **enterprise-grade systems**.
