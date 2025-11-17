# ADR-002 – Arquitectura Hexagonal como base

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## Contexto

La plantilla de seguridad debe ser:

- Reutilizable en proyectos de distintos dominios (energía, logística, banca, etc.).
- Fácil de testear sin depender del framework web o de persistencia.
- Independiente de detalles de infraestructura (JWT provider, base de datos, etc.).
- Suficientemente limpia como para servir de referencia de buenas prácticas.

Se evaluaron varias aproximaciones: arquitectura en capas tradicional, arquitectura modular de Spring y arquitectura hexagonal.

## Decisión

Adoptar **Arquitectura Hexagonal (Ports & Adapters)** como base, con inspiración **DDD** para el modelo de dominio.

Se organizarán las capas principales en:

- `domain` → modelo y reglas de negocio (User, Role, Scope, UserStatus, excepciones).
- `application` → casos de uso (login, refresh, me, register).
- `infrastructure` → adaptadores (JWT, persistencia, filtros, métricas).
- `web` → controladores REST y DTOs.

## Alternativas consideradas

1. **Arquitectura en capas clásica (Controller → Service → Repository)**
   - ✔ Sencilla y conocida.
   - ✖ Mezcla lógica de negocio con detalles de infraestructura.
   - ✖ Dificulta el reemplazo de persistencia o proveedores de JWT.

2. **Arquitectura basada en módulos de Spring (submódulos por feature)**
   - ✔ Buena separación por funcionalidades.
   - ✖ Fuertemente acoplada a Spring.
   - ✖ El dominio sigue con dependencia de framework.

3. **Monolito simple sin separación clara**
   - ✔ Rápida para MVPs.
   - ✖ No alineada con el objetivo de servir como plantilla enterprise.

## Justificación técnica

- La Arquitectura Hexagonal permite que el **dominio y los casos de uso no dependan de Spring**, ni de JPA, ni de Nimbus.
- Facilita tests unitarios puros sobre `application` y `domain` sin levantar el contexto.
- Hace que los detalles de infraestructura (JWT, DB, métricas) sean plug-and-play, a través de interfaces (ports).

## Consecuencias

**Positivas:**

- Código más limpio, mantenible y escalable.
- Facilidad para reemplazar adaptadores (por ejemplo, cambiar de JPA a otro tipo de persistencia).
- El proyecto sirve como referencia clara de buenas prácticas de arquitectura.

**Negativas:**

- Mayor complejidad conceptual para desarrolladores sin experiencia en DDD/Hexagonal.
- Requiere disciplina para no “saltarse” las capas y acoplar web o infra al dominio.
