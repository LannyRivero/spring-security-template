# 🚨 Authentication & Identity — Domain Error Codes

This document centralizes all domain-level error codes used in the
Spring Security Template for authentication, authorization, identity
validation, and user lifecycle management.

These codes are:

Machine-readable

Stable across releases

Used internally by Domain → Application → Web layers

Reported in API responses via ApiError

Optimized for observability (Kibana, Grafana, ELK, OpenTelemetry)

Tracers for debugging and audit

All error codes follow the naming convention:

ERR-AUTH-XXX

📚 Table of Contents

Authentication Errors

User Lifecycle Errors

Value Object Validation Errors

Reserved Ranges

Mapping to HTTP Status Codes

🔐 Authentication Errors
ERR-AUTH-001 — Invalid Credentials

Thrown when:

Username does not exist, or

Password does not match

Used in authentication flows.

→ HTTP 401 Unauthorized

👤 User Lifecycle Errors
ERR-AUTH-002 — User Locked

User locked due to too many failed login attempts or security rules.

→ HTTP 403 Forbidden

ERR-AUTH-003 — User Disabled

Account disabled by an administrator.

→ HTTP 403 Forbidden

ERR-AUTH-004 — User Deleted

Account soft-deleted; authentication must be denied permanently.

→ HTTP 403 Forbidden

ERR-AUTH-005 — User Not Found

No matching user exists in the system.

→ HTTP 404 Not Found

🧩 Value Object Validation Errors
ERR-AUTH-010 — Invalid Email

Email fails domain validation rules:

Malformed

Too long

Blank

→ HTTP 400 Bad Request

ERR-AUTH-011 — Invalid Username

Username violates domain constraints:

Too short / too long

Invalid characters

Starts/ends with '.'

Contains consecutive dots

→ HTTP 400 Bad Request

ERR-AUTH-012 — Invalid Password Hash

Password hash stored in the system is malformed or invalid.

(Should never happen unless storage corruption or bug)

→ HTTP 500 Internal Server Error

ERR-AUTH-013 — Invalid Role

Role name violates required pattern:

ROLE_[A-Z0-9_-]+


→ HTTP 400 Bad Request

ERR-AUTH-014 — Invalid Scope

Scope violates IAM-format requirement:

resource:action


→ HTTP 400 Bad Request

🗂 Reserved Ranges

To future-proof the template, the following ranges are reserved:

Range	Category
ERR-AUTH-020–029	JWT & Token Errors
ERR-AUTH-030–039	Scope / Permission Policy Violations
ERR-AUTH-040–049	Refresh Token & Rotation Policies
ERR-AUTH-050–059	Session / Concurrency Control
ERR-AUTH-060–099	Multi-Tenant and Organization IAM Rules
🌐 Mapping to HTTP Status Codes
Error Code	HTTP Status	Description
ERR-AUTH-001	401 Unauthorized	Invalid login credentials
ERR-AUTH-002	403 Forbidden	Locked user
ERR-AUTH-003	403 Forbidden	Disabled user
ERR-AUTH-004	403 Forbidden	Deleted user
ERR-AUTH-005	404 Not Found	User not found
ERR-AUTH-010	400 Bad Request	Invalid email
ERR-AUTH-011	400 Bad Request	Invalid username
ERR-AUTH-012	500 Internal Server Error	Invalid password hash
ERR-AUTH-013	400 Bad Request	Invalid role
ERR-AUTH-014	400 Bad Request	Invalid scope
🧭 Summary

Your Spring Security Template now has a complete, consistent, enterprise-grade identity error taxonomy.
This enables:

Centralized error management

Clean translation to HTTP responses

Precise debugging

Better UX on client side

Better dashboards in monitoring tools

Zero ambiguity in authentication flows