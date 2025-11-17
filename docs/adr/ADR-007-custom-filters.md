# ADR-007 — Elección de Filtros Personalizados
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado

---

## 🎯 Contexto

Además del filtro estándar de autenticación JWT, un sistema enterprise moderno requiere mecanismos adicionales de seguridad y observabilidad:

- Mitigar ataques de fuerza bruta  
- Añadir cabeceras de seguridad recomendadas por OWASP  
- Trazabilidad entre microservicios (Correlation-ID)  
- Prevenir cache de tokens  
- Controlar comportamiento en entornos dev/test/prod  

Spring Security provee un sistema flexible basado en filtros; por tanto, los filtros deben:

1. Ser independientes del dominio  
2. Ser ordenados correctamente  
3. Reducir acoplamiento  
4. Ser fáciles de activar/desactivar  

---

## 🧠 Decisión

Se definen e implementan 5 filtros personalizados:

### 1. **LoginRateLimitingFilter**  
Previene intentos repetidos de login → evita brute-force.

### 2. **SecurityHeadersFilter**  
Añade cabeceras OWASP:  
- HSTS  
- X-Frame-Options  
- X-Content-Type-Options  
- Referrer-Policy  
- Strict-Transport-Security  

### 3. **CorrelationIdFilter**  
Añade `X-Correlation-ID` a todas las peticiones → trazabilidad.

### 4. **AuthNoCacheFilter**  
Bloquea el cacheo de respuestas sensibles de auth.

### 5. **JwtAuthorizationFilter**  
Valida JWT, claims, expiración, firma y scopes.

Todos los filtros se ordenan en `FilterOrder.java` para evitar inconsistencias.

---

## ✔ Razones principales

### 1. Seguridad avanzada (OWASP ASVS)
Cabeceras, cache-control, mitigación brute-force → nivel enterprise.

### 2. Observabilidad real
Sin Correlation-ID no se puede trazar errores entre microservicios.

### 3. Full compliance
Cumple mejores prácticas de banca, fintech y empresas.

### 4. Separación de responsabilidades
Cada filtro hace **una cosa y solo una cosa** (SRP).

---

## 🧩 Alternativas consideradas

### 1. No usar filtros propios  
✗ Menos seguridad  
✗ No hay tracing  
✗ No cumple estándares enterprise  

### 2. Un solo filtro gigante  
✗ Mala práctica  
✗ Difícil de mantener  
✗ No cumple SRP  

---

## 📌 Consecuencias

### Positivas
- Seguridad reforzada  
- Observabilidad mejorada  
- Código desacoplado  
- Fácil testing  

### Negativas
- Mayor cantidad de clases  
- Más configuración en SecurityConfig  

---

## 📤 Resultado

El template implementa filtros:

- Separados  
- Testeables  
- Ordenados  
- Activables vía perfiles  

Listos para producción.

