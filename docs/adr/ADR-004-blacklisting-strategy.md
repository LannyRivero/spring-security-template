# ADR-004 – Estrategia de Blacklisting

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## Contexto

Aunque los JWT son stateless por diseño, existen situaciones en las que es necesario revocar tokens antes de su expiración natural:

- Logout explícito del usuario.
- Bloqueo o eliminación de la cuenta.
- Rotación de Refresh Tokens.
- Posible compromiso de credenciales.

## Decisión

Introducir un componente `TokenBlacklistGateway` que permita:

- Registrar tokens (por `jti`) como revocados.
- Consultar si un token está en blacklist durante la validación.

La implementación concreta del gateway podrá variar según el entorno:

- **dev/test:** InMemory.
- **prod:** Redis, base de datos u otra store persistente.

## Alternativas consideradas

1. **No implementar blacklisting**
   - ✔ Menor complejidad.
   - ✖ No se puede hacer logout real.
   - ✖ No se pueden invalidar tokens comprometidos.

2. **Reducir al mínimo la expiración de Access Tokens**
   - ✔ Reduce el impacto temporal de un robo.
   - ✖ No resuelve casos de Refresh Token robado.
   - ✖ Peor UX si la expiración es muy corta.

3. **Modificar secret/clave para invalidar todos los tokens**
   - ✔ Método extremo de revocación global.
   - ✖ Invalida todas las sesiones (afecta a todos los usuarios).
   - ✖ Difícil de usar en producción sin impacto masivo.

## Justificación técnica

- El blacklisting ofrece un punto de control intermedio entre:
  - No tener revocación.
  - Tener que invalidar absolutamente todos los tokens.
- Se integra de forma limpia con la validación estándar de JWT:
  - Firma válida
  - No expirado
  - No revocado (`TokenBlacklistGateway`)

## Consecuencias

**Positivas:**

- Permite logout real y revocación temprana de tokens.
- Reduce impacto en caso de compromiso.
- Es compatible con la estrategia de Refresh Token Rotation.

**Negativas:**

- Necesita almacenamiento adicional para IDs de tokens revocados.
- Añade una consulta extra en el flujo de validación de tokens (con impacto mínimo si se usa una store rápida).
