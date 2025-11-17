# ADR-007 – Elección de filtros personalizados

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## Contexto

Además de la cadena de filtros de Spring Security, el sistema necesita:

- Añadir cabeceras de seguridad (HSTS, XSS-Protection, CSP, etc.).
- Limitar intentos de login (rate limiting).
- Propagar un `X-Correlation-ID` para trazabilidad.
- Evitar cache de respuestas sensibles.

## Decisión

Implementar los siguientes filtros propios:

- `LoginRateLimitingFilter`
- `SecurityHeadersFilter`
- `CorrelationIdFilter`
- `AuthNoCacheFilter`

Y definir su posición relativa mediante una enumeración de orden (`FilterOrder`).

## Alternativas consideradas

1. **Confiar solo en los filtros por defecto de Spring Security**
   - ✔ Menos código propio.
   - ✖ No cubre todas las cabeceras de seguridad recomendadas.
   - ✖ No da control fino sobre rate limiting ni correlation IDs.

2. **Delegar completamente en API Gateway**
   - ✔ El gateway puede manejar cabeceras y rate limiting.
   - ✖ No todas las instalaciones tienen gateway.
   - ✖ Menos control en entornos locales o monolíticos.

## Justificación técnica

- Los filtros personalizados permiten que la plantilla sea útil incluso sin gateway.
- Permiten tener un punto único para:
  - Medir métricas de seguridad.
  - Asegurar cabeceras.
  - Aplicar rate limiting de login.

## Consecuencias

**Positivas:**

- Mayor seguridad desde la propia aplicación.
- Mejor trazabilidad de peticiones.
- Plantilla utilizable en distintos escenarios de despliegue.

**Negativas:**

- Incrementa el número de componentes a mantener.
- Necesidad de tener tests específicos para los filtros.
