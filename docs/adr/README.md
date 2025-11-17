🧠 Architecture Decision Records (ADR) – Índice

Este directorio contiene todas las decisiones arquitectónicas formales tomadas para el proyecto Spring Security Template.
Cada ADR documenta una decisión importante, junto con su contexto, alternativas consideradas, justificación y consecuencias.

Estos ADRs siguen el estándar de la industria usado en proyectos enterprise y ayudan a mantener transparencia y trazabilidad técnica.

📑 Lista de ADRs
🔐 Seguridad y Autenticación
Nº	Título	Enlace
ADR-001	Algoritmo de firma JWT: RSA vs HMAC	ADR-001-rsa-vs-hmac.md

ADR-003	Estrategia de Refresh Token Rotation	ADR-003-refresh-token-rotation.md

ADR-004	Estrategia de Blacklisting	ADR-004-blacklisting-strategy.md

ADR-005	Uso de Nimbus JOSE + JWT	ADR-005-nimbus-vs-jjwt.md

ADR-008	Fuentes de claves RSA (classpath, filesystem, keystore)	ADR-008-rsa-key-sources.md
🧩 Arquitectura
Nº	Título	Enlace
ADR-002	Arquitectura Hexagonal como base del proyecto	ADR-002-hexagonal-architecture.md

ADR-006	Modelo RBAC + Scope Policy (ABAC)	ADR-006-rbac-scope-policy.md

ADR-007	Elección de filtros personalizados	ADR-007-custom-filters.md
🛠️ Configuración y entornos
Nº	Título	Enlace
ADR-009	InMemoryProviders en perfil dev	ADR-009-inmemory-providers-dev.md

ADR-010	Observabilidad con Prometheus	ADR-010-observability-prometheus.md
📘 ¿Qué es un ADR?

Un Architectural Decision Record es un documento breve que deja constancia de:

El contexto técnico del momento

La decisión tomada

Alternativas evaluadas

Consecuencias positivas y negativas

Justificación técnica

Sirven para que cualquier persona —actual o futura— entienda por qué la arquitectura es como es.

⭐ Recomendación de uso

Cada cambio relevante en la arquitectura debe crear un nuevo ADR.

Los ADRs no se sustituyen: se crean nuevos documentos que “revocan” los anteriores.

El repositorio debe usarse como histórico de decisiones técnicas.