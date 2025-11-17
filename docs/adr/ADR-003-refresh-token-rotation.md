# ADR-003 – Refresh Token Rotation

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## Contexto

El sistema ofrece autenticación mediante:

- Access Tokens de corta duración.
- Refresh Tokens de mayor duración.

Los Refresh Tokens, si se comprometen, pueden permitir que un atacante mantenga una sesión activa sin conocer la contraseña del usuario. Es necesario reducir este riesgo manteniendo una buena experiencia de usuario.

## Decisión

Implementar una estrategia de **Refresh Token Rotation**, preparada en la plantilla, donde:

- Cada vez que se use un Refresh Token válido:
  - Se emite un **nuevo Refresh Token**.
  - El Refresh Token anterior se marca como inválido (revocado).
- La revocación se hace mediante el `jti` (ID de token) y el `TokenBlacklistGateway`.

## Alternativas consideradas

1. **No usar refresh tokens**
   - ✔ Diseño más simple.
   - ✖ Obliga al usuario a autenticarse con credenciales con mucha frecuencia.
   - ✖ No encaja con flujos modernos de UX.

2. **Refresh tokens sin rotación**
   - ✔ Implementación sencilla.
   - ✖ Un refresh robado tiene una ventana de uso muy larga.
   - ✖ Difícil revocar de forma granular.

3. **Sesiones solo con Access Tokens muy cortos**
   - ✔ Simplifica el modelo.
   - ✖ Experiencia de usuario pobre (relogin continuo).
   - ✖ Requiere demasiada tolerancia al fallo en el cliente.

## Justificación técnica

- La rotación de Refresh Tokens **es la práctica recomendada en OAuth2/OIDC**.
- Permite invalidar un refresh en cuanto se use (one-time token) y aplicar políticas de seguridad más estrictas.
- La plantilla incluye infraestructura de revocación a través de `TokenBlacklistGateway`.

## Consecuencias

**Positivas:**

- Reduce significativamente el impacto del robo de un Refresh Token.
- Permite implementar políticas de seguridad avanzadas sin rehacer el modelo.
- Alinea la plantilla con estándares modernos de seguridad.

**Negativas:**

- Complejidad adicional en la gestión de tokens (generación + revocación).
- Necesidad de almacenamiento para token IDs revocados (idealmente Redis u otra store rápida).
