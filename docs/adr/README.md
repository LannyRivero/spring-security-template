# 🧠 Architecture Decision Records (ADR) – Índice

Este directorio contiene todas las decisiones arquitectónicas formales tomadas para el proyecto Spring Security Template.

Cada ADR documenta una decisión importante, junto con su contexto, alternativas consideradas, justificación y consecuencias.

Estos ADRs siguen el estándar de la industria usado en proyectos enterprise y ayudan a mantener transparencia y trazabilidad técnica.

## 📑 Lista de ADRs

### 🔐 Seguridad y Autenticación

- ADR-001	Algoritmo de firma JWT: RSA vs HMAC	
- ADR-003	Estrategia de Refresh Token Rotation	
- ADR-004	Estrategia de Blacklisting	
- ADR-005	Uso de Nimbus JOSE + JWT	
- ADR-008	Fuentes de claves RSA (classpath, filesystem, keystore)

### 🧩 Arquitectura

- ADR-002	Arquitectura Hexagonal como base del proyecto	
- ADR-006	Modelo RBAC + Scope Policy (ABAC)	
- ADR-007	Elección de filtros personalizados	

### 🛠️ Configuración y entornos

- ADR-009	InMemoryProviders en perfil dev	
- ADR-010	Observabilidad con Prometheus	

## 📘 ¿Qué es un ADR?

Un Architectural Decision Record es un documento breve que deja constancia de:

- El contexto técnico del momento
- La decisión tomada
- Alternativas evaluadas
- Consecuencias positivas y negativas
- Justificación técnica

Sirven para que cualquier persona —actual o futura— entienda por qué la arquitectura es como es.

⭐ Recomendación de uso

- Cada cambio relevante en la arquitectura debe crear un nuevo ADR.

  ### Los ADRs no se sustituyen: se crean nuevos documentos que “revocan” los anteriores.
  
- El repositorio debe usarse como histórico de decisiones técnicas.
