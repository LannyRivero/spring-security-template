# 🚨 Authentication Domain Error Codes

This document centralizes internal error codes associated with
authentication-related domain exceptions.

These error codes are:

- Machine-readable
- Stable across releases
- Intended for observability, dashboards, and correlation
- Exposed via ApiError in the infrastructure/web layer

---

## ERR-AUTH-001 — Invalid Credentials
Thrown when a user attempts to authenticate with an invalid password
or unknown username.

→ Maps to: **HTTP 401 Unauthorized**

---

## ERR-AUTH-002 — User Locked
The user account is temporarily locked due to too many failed login attempts.

→ Maps to: **HTTP 403 Forbidden**

---

## ERR-AUTH-003 — User Disabled
The user account has been disabled by an administrator.

→ Maps to: **HTTP 403 Forbidden**

---

## ERR-AUTH-004 — User Deleted
The account has been soft-deleted and must not authenticate.

→ Maps to: **HTTP 403 Forbidden**
