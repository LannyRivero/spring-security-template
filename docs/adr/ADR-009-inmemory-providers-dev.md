# ADR-009 – InMemoryProviders por perfil dev

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## Contexto

En entornos de desarrollo es deseable:

- Tener arranques muy rápidos.
- Evitar dependencias externas (DB, Redis, etc.).
- Permitir probar la plantilla sin configuración compleja.

## Decisión

Para el perfil **`dev`** se implementan proveedores en memoria:

- `InMemoryRoleProvider`
- `InMemoryScopePolicy`
- `InMemoryTokenBlacklistGateway`

Estos permiten usar la plantilla de seguridad sin necesidad de configurar una base de datos ni una cache externa.

## Alternativas consideradas

1. **Siempre usar DB real**
   - ✔ Entorno más “real”.
   - ✖ Ralentiza el arranque.
   - ✖ Añade fricción innecesaria a quien solo quiere probar la plantilla.

2. **Mockear todo en tests pero sin soporte real dev**
   - ✖ No ayuda en pruebas manuales de la API.

## Justificación técnica

- En desarrollo se favorece la productividad sobre el realismo absoluto del entorno.
- Al tener adaptadores InMemory, el desarrollador puede probar login, refresh, scopes, etc. sin montar infraestructura adicional.

## Consecuencias

**Positivas:**

- Onboarding muy rápido para nuevos usuarios de la plantilla.
- Menos puntos de fallo en dev.
- Permite centrar la atención en la seguridad, no en la base de datos.

**Negativas:**

- El comportamiento en prod (con DB/cache real) puede diferir ligeramente.
- Es necesario avisar claramente en la documentación de que estos proveedores son solo para dev.
