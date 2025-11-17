# ADR-005 – Uso de Nimbus JOSE + JWT

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## Contexto

La plantilla necesita una biblioteca para:

- Firmar y validar JWT.
- Gestionar claves (JWK).
- Posibilitar JWE (encriptación) en el futuro.
- Integrarse con ecosistemas OAuth2/OIDC.

Las opciones principales fueron **JJWT** y **Nimbus JOSE + JWT**.

## Decisión

Elegir **Nimbus JOSE + JWT** como biblioteca estándar para el manejo de JWT y JOSE.

## Alternativas consideradas

1. **JJWT**
   - ✔ API muy sencilla.
   - ✔ Fácil para ejemplos simples.
   - ✖ Limitado en soporte JOSE.
   - ✖ No orientado a JWE ni escenarios avanzados enterprise.

2. **Otras librerías más ligeras**
   - ✔ Menor huella.
   - ✖ No ofrecen el mismo nivel de soporte JOSE/JWK/JWE.

## Justificación técnica

- Nimbus ofrece soporte completo para:
  - JWS, JWK, JWE, JWT, JOSE.
- Es ampliamente usada en:
  - Servidores OAuth2 / OIDC.
  - Soluciones de SSO.
  - Entornos bancarios y de alta seguridad.
- Permite evolucionar la plantilla hacia:
  - JWE (tokens encriptados).
  - JWK sets expuestos, si se añadiera un Authorization Server.

## Consecuencias

**Positivas:**

- La plantilla se alinea con estándares enterprise.
- La lógica de token es extensible y flexible.
- Se simplifica la integración futura con OAuth2 / OIDC.

**Negativas:**

- Curva de aprendizaje algo mayor comparado con JJWT.
- Más opciones y configuraciones, lo que requiere guías claras (README y ADRs).
