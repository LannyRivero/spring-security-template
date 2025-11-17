# ADR-006 – Modelo RBAC + Scope Policy (ABAC)

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## Contexto

El sistema de seguridad debe apoyar:

- Autorización basada en roles (ROLE_ADMIN, ROLE_USER, etc.).
- Permisos más finos de tipo “scope” (`profile:read`, `simulation:write`, etc.).
- Anotaciones a nivel de controlador y caso de uso (`@PreAuthorize`).

## Decisión

Adoptar un modelo mixto:

- **RBAC (Role-Based Access Control)** para acceso macro.
- **Scopes como permisos específicos (ABAC ligero)**, evaluados por una **Scope Policy** configurable.

## Alternativas consideradas

1. **Solo roles**
   - ✔ Sencillo de entender.
   - ✖ No escala bien cuando aumentan las acciones específicas.

2. **Solo permisos (scopes)**
   - ✔ Muy flexible.
   - ✖ Difícil de manejar mentalmente sin agrupar en roles.
   - ✖ Complejidad para equipos menos maduros.

3. **Listas de control por endpoint sin modelo formal**
   - ✖ Difícil de mantener y revisar.
   - ✖ No reutilizable ni expresivo.

## Justificación técnica

- El combo roles + scopes es el patrón común en APIs modernas:
  - Rol = “quién eres”
  - Scope = “qué puedes hacer”
- `ScopePolicy` permite mapear roles → scopes de forma explícita.
- El JWT incluye roles y scopes como claims separados, lo que simplifica la evaluación.

## Consecuencias

**Positivas:**

- Autorización robusta, clara y extensible.
- La plantilla se adapta a distintos dominios sin cambiar la infraestructura de seguridad.
- Facilidad para documentar qué rol/ scope permite qué acción.

**Negativas:**

- Mayor complejidad que sólo usar roles.
- Requiere disciplina en el diseño de scopes para no generar caos de permisos.
