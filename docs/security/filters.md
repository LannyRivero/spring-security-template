# 🛡 Filtros de Seguridad

El sistema implementa una cadena de filtros de seguridad tipo enterprise.

---

## 🔍 Orden de filtros

1. CorrelationIdFilter
2. SecurityHeadersFilter
3. LoginRateLimitingFilter
4. AuthNoCacheFilter
5. JwtAuthorizationFilter
6. Controladores / servicio

---

## 📌 CorrelationIdFilter
- Inserta header `X-Correlation-ID`
- Útil para tracing, logs, debugging

---

## 📌 SecurityHeadersFilter
Agrega cabeceras de seguridad:

- HSTS
- X-Frame-Options
- XSS Protection
- Content-Security-Policy (base)
- NoSniff

---

## 📌 LoginRateLimitingFilter
- Protección contra brute-force
- Límite por IP y usuario
- Responde 429 cuando se excede

---

## 📌 AuthNoCacheFilter
Evita que navegadores cacheen tokens:

- Cache-Control
- Pragma
- Expires

---

## 📌 JwtAuthorizationFilter
- Extrae el JWT
- Valida firma con Nimbus
- Valida claims, expiración, roles, scopes
- Pobla el SecurityContext