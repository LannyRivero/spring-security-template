# ADR-001 – Algoritmo de firma JWT: RSA vs HMAC

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## Contexto

La plantilla de seguridad requiere firmar y validar JWTs de forma segura.  
Los algoritmos más utilizados en la industria son:

- HMAC (HS256/HS384/HS512) → clave simétrica
- RSA (RS256/RS384/RS512) → clave asimétrica

La solución debe funcionar en:

- Entornos de desarrollo y test (configuración sencilla)
- Entornos productivos corporativos (seguridad fuerte, rotación de claves)
- Escenarios distribuidos (API Gateway, múltiples microservicios)

## Decisión

Se adopta la siguiente estrategia:

- **Producción:** algoritmo de firma recomendado → **RSA** (asimétrico).
- **Desarrollo / Test:** se permite **HMAC** o RSA demo por simplicidad.
- El algoritmo será configurable vía propiedad: `security.jwt.algorithm`.

## Alternativas consideradas

1. **Solo HMAC**
   - ✔ Fácil de configurar (una sola clave base64).
   - ✖ Menos seguro en arquitecturas distribuidas (todos comparten la misma clave).
   - ✖ Complica escenarios donde distintos servicios solo deberían tener la clave pública.

2. **Solo RSA**
   - ✔ Muy seguro y estándar en entornos enterprise.
   - ✖ Aumenta la complejidad inicial en entornos locales y de CI.

3. **Otros algoritmos (EC, EdDSA)**
   - ✔ Modernos y eficientes.
   - ✖ No aportan un beneficio inmediato para el alcance actual.
   - ✖ Añaden complejidad innecesaria en esta primera versión.

## Justificación técnica

- RSA permite separar:
  - **Clave privada** → solo en el servicio emisor.
  - **Clave pública** → compartida con gateways u otros microservicios.
- Cumple mejor las recomendaciones de OWASP ASVS y prácticas de JWT en ecosistemas distribuidos.
- HMAC se mantiene como opción opcional para facilitar el desarrollo local y los entornos de test.

## Consecuencias

**Positivas:**

- Mayor seguridad en producción gracias a claves asimétricas.
- Modelo compatible con API Gateways y validación de tokens en múltiples servicios.
- Soporte sencillo para rotación de claves RSA en el futuro.
- Flexibilidad para usar HMAC cuando se priorice sencillez (dev/test).

**Negativas:**

- Configuración de RSA requiere más pasos (keystore, claves, secretos).
- Se necesita una abstracción (`TokenProvider`) para que el resto del código sea agnóstico al algoritmo.
