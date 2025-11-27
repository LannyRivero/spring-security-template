📘 Application Layer – Clean Architecture Overview

La capa application implementa los casos de uso del sistema de autenticación y autorización del proyecto.
Es completamente agnóstica a la infraestructura, altamente testable y sigue los principios de:

Arquitectura hexagonal (Ports & Adapters)

Domain-Driven Design (DDD)

CQRS ligero

SOLID

Test-Driven Development

Aquí se define qué hace la aplicación, no cómo se implementa técnicamente.

🧱 Objetivo

La misión de esta capa es:

Exponer casos de uso (use cases).

Orquestar la lógica de negocio usando:

Policies (reglas de seguridad)

Domain services

Ports (puertos/in/out) para comunicarse con el exterior.

Ofrecer DTOs contractuales (commands, queries, results).

Mantenerse totalmente independiente de:

JPA

Redis

Nimbus JOSE / JWT

Spring Security

Bases de datos

Servicios externos

La infraestructura se conecta a esta capa, nunca al revés.

🧩 Estructura de Paquetes
application/
 ├── auth/
 │    ├── command/
 │    ├── query/
 │    ├── result/
 │    ├── service/
 │    ├── validator/
 │    ├── handler/
 │    ├── factory/
 │    ├── creator/
 │    ├── resolver/
 │    ├── policy/
 │    ├── port/
 │    │     ├── in/
 │    │     └── out/
 │    └── dto/
 └── common/

🧠 Filosofía de diseño
✔ 1. Use Cases primero

La capa application define qué casos de uso ofrece el sistema:

Login

Refresh

Me

Cambio de contraseña

Registro en entorno dev

Esto está centralizado en AuthUseCase.

✔ 2. Separación clara de comandos, queries y resultados

Commands → acciones que modifican estado.

Queries → lecturas puras.

Results → datos que regresan los casos de uso.

Ejemplos:

LoginCommand
RefreshCommand
RegisterCommand
MeQuery

JwtResult
MeResult
IssuedTokens
RoleScopeResult

✔ 3. Puertos (Ports) para desacoplar infraestructura

Los casos de uso dependen de interfaces, no de implementaciones.

Ejemplos de puertos OUT:

UserAccountGateway

TokenProvider

RefreshTokenStore

TokenBlacklistGateway

SessionRegistryGateway

RoleProvider

AuditEventPublisher

AuthMetricsService

La infraestructura (JPA/Redis/Nimbus/etc.) implementa estas interfaces.

✔ 4. Policies: seguridad definida en la lógica, no en Frameworks

El comportamiento de seguridad NO se define en Spring Security.
Se define aquí.

Policies:

LoginAttemptPolicy

PasswordPolicy

RefreshTokenPolicy

RotationPolicy

SessionPolicy

TokenPolicyProperties

Esto te permite cambiar el comportamiento de seguridad sin modificar servicios.

✔ 5. Servicios de aplicación (application services)

Cada caso de uso tiene su propio servicio dedicado, cumpliendo SRP:

LoginService

RefreshService

MeService

ChangePasswordService

DevRegisterService

Estos servicios:

coordinan políticas

validan comandos

consultan puertos

aplican lógica de negocio

emiten eventos de auditoría

registran métricas

✔ 6. Helpers desacoplados: Issuer, Factory, Handler, Validator

Componentes especializados:

TokenIssuer

TokenSessionCreator

TokenRotationHandler

TokenRefreshResultFactory

RoleScopeResolver

RefreshTokenValidator

AuthenticationValidator

El objetivo es que ningún servicio haga demasiadas cosas.

✔ 7. Eventos, métricas y trazabilidad integrados

Cada operación crítica emite o registra:

Eventos mediante AuditEventPublisher

Métricas mediante AuthMetricsService

Logs estructurados con MDC (traceId, username)

Esto refleja una arquitectura preparada para entornos enterprise.

🧬 Mini matriz: UseCase → Ports → Policies → Domain
📌 Ejemplo: Login
Capa	Elementos
UseCase	AuthUseCaseImpl.login()
Services	LoginService
Ports OUT	UserAccountGateway, TokenProvider, TokenBlacklistGateway, SessionRegistryGateway, RefreshTokenStore, AuditEventPublisher, AuthMetricsService
Policies	LoginAttemptPolicy, PasswordPolicy, SessionPolicy, TokenPolicyProperties
Domain	User, Role, Scope, PasswordHasher, JwtClaimsDTO

(Ver README extendido para resto de use cases.)

🧪 Testing

La capa application está diseñada para ser totalmente testeable.

Incluye tests para:

Commands

Results

Services

Policies

Validators

Factories

Handlers

Resolvers

Los tests usan:

JUnit 5

Mockito

AssertJ

@DisplayName para clarificar intenciones

Ningún test requiere base de datos o contexto real.

🔐 Beneficios de esta arquitectura

Total independencia de frameworks.

Fácil de testear al 100%.

Permite cambiar la infraestructura sin tocar la lógica.

Escalable: añadir nuevos casos de uso es trivial.

Seguridad definida en código propio, no en anotaciones mágicas.

Ideal como plantilla base para cualquier proyecto enterprise.

📦 Convenciones

Todos los DTOs y commands son immutables (record).

Excepciones específicas del dominio (no se lanzan excepciones de infra).

Servicios documentados con Javadoc detallado.

Nombres expresivos y consistentes.

🏁 Conclusión

La capa application implementa la arquitectura empresarial del proyecto.
Aquí vive la lógica de autenticación, las políticas de seguridad y los contratos del sistema.

Todo está pensado para:

rápidez

robustez

testabilidad

flexibilidad

claridad arquitectónica

Es una base sólida para cualquier microservicio de seguridad moderno.