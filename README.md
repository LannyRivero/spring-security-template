# 🛡️ Spring Security Template
Esta plantilla está diseñada para ser el *núcleo estándar de seguridad* en ecosistemas de microservicios, con autenticación empresarial basada en Nimbus JOSE + JWT, cumplimiento OWASP y arquitectura hexagonal totalmente desacoplada.
Está optimizada para entornos de alta seguridad, escalabilidad y despliegues corporativos.

![Java](https://img.shields.io/badge/Java-21-blue)
![SpringBoot](https://img.shields.io/badge/Spring_Boot-3.4.x-brightgreen)
![Security](https://img.shields.io/badge/Spring_Security-6.x-orange)
![Nimbus](https://img.shields.io/badge/Nimbus_JOSE+JWT-enterprise-purple)
![Coverage](https://img.shields.io/badge/Coverage-%E2%89%A570%25-yellow)
![License](https://img.shields.io/badge/License-MIT-lightgray)
![Status](https://img.shields.io/badge/Production_Ready-YES-success)

---
## 🌟 Visión General

Spring Security Template es una plantilla enterprise, modular y extensible que proporciona un stack completo de autenticación y autorización listo para producción.
Implementa Nimbus JOSE + JWT, una librería utilizada en banca, fintech y sistemas corporativos.
Es compatible con los estándares:

- JWS (JSON Web Signature)
- JWT (JSON Web Token)
- JWK (JSON Web Key)
- JWE (JSON Web Encryption)
- JOSE completo

Esto permite una seguridad fuerte, flexible y alineada con los estándares corporativos actuales.

### ❌ Por qué no usamos JJWT

JJWT es simple y rápido, pero tiene limitaciones:

- No soporta JOSE completo
- No permite JWE
- Menor extensibilidad
- Problemas para integrarlo con OAuth2 / OIDC
- No apto para escalado enterprise

Por eso usamos **Nimbus JOSE + JWT**, el estándar en banca, fintech y sistemas de alto nivel.

### 🚀 Incluye:

🔐 Autenticación Nimbus JOSE + JWT con Access + Refresh

🔏 Firma RSA o HMAC, completamente intercambiables

🧩 Arquitectura Hexagonal + DDD

🛡 Filtros enterprise: Rate Limiting, Security Headers, Correlation-ID

⚡ Integración con microservicios (RenewSim, Buzón Inteligente, etc.)

📊 Observabilidad (Prometheus)

🧪 Testing profesional con JUnit + Mockito + Testcontainers

🚀 Listo para Docker, Kubernetes y entornos corporativos

---

## 🧱 Arquitectura (Hexagonal + Clean Architecture)

```bash
application
└── auth
    ├── command → Casos de uso (LoginCommand, RefreshCommand)
    ├── port.in/out → Interfaces (AuthUseCase, TokenProvider, etc.)
    ├── result → Resultados (JwtResult, MeResult)
    └── service → Implementaciones (AuthUseCaseImpl)

domain
└── model
    ├── User, Role, Scope, UserStatus
    └── exception → UserLockedException, UserDisabledException

infrastructure
├── jwt → NimbusJwtTokenProvider, RsaKeyProviders, JwtUtils
├── security.filter → JwtAuthorization, RateLimiter, SecurityHeaders
├── security.handler → CustomAuthEntryPoint, AccessDeniedHandler
├── config → OpenAPI, CORS, Properties
└── persistence → Adaptadores JPA / InMemory (UserAccountGateway)

web
└── auth
    ├── controller
    └── dto (AuthRequest, RefreshRequest, AuthResponse)

```
---
## 🧭 Diagrama C4
<img width="550" height="728" alt="1" src="https://github.com/user-attachments/assets/2e918aef-e731-4f42-a8e5-4246d0b0ee82" />

---

## 🔐 Flujo de Seguridad 
<img width="1140" height="488" alt="2" src="https://github.com/user-attachments/assets/712bf836-12b2-4045-98ce-dea71d35fb0c" />

---

## 🚀 Características Enterprise
### 🔐 Autenticación Nimbus JOSE + JWT (Nivel Corporativo)

- Access tokens autocontenidos
- Refresh tokens firmados
- Firma RSA 2048 bits o HMAC (base64)

#### Claims completos:

- sub, roles, scopes, jti, iss, iat, exp
- Soporte para clave rotativa
- Blacklisting
- Refresh Token Rotation

#### KeyProviders:

- classpath
- filesystem
- keystore

### 🧩 Arquitectura Hexagonal real

- Reglas de negocio en domain
- Casos de uso en application
- Infra totalmente desacoplada
- DTOs aislados en web
- Filtros separados del dominio

### 🛡 Seguridad Multicapa

- JwtAuthorizationFilter
- LoginRateLimitingFilter
- SecurityHeadersFilter
- CorrelationIdFilter
- AuthNoCacheFilter
- CustomAuthEntryPoint
- CustomAccessDeniedHandler

#### Cumple:

- OWASP ASVS
- OAuth2/JWT best practices
- PCI-DSS (base)

### 📊 Observabilidad

- Métricas Prometheus
- Contadores de login y fallos
- MDC con X-Correlation-ID

### 🧪 Testing Profesional

- Tests RSA/HMAC
- Tests Nimbus JWT
- Tests de filtros
- Tests del SecurityConfig
- Slice tests (@WebMvcTest)
- Testcontainers para integración
- Cobertura mínima: ≥70%

---

## 🔧 Endpoints principales

| Método | Ruta                    | Descripción          | Público |
| ------ | ----------------------- | -------------------- | ------- |
| POST   | `/api/v1/auth/login`    | Autentica usuario    | ✔       |
| POST   | `/api/v1/auth/refresh`  | Reemite Access Token | ✔       |
| POST   | `/api/v1/auth/register` | Dev-only             | ✔       |
| GET    | `/api/v1/auth/me`       | Usuario actual       | 🔒      |
| GET    | `/api/v1/secure/ping`   | Recurso protegido    | 🔒      |


---

## 🧩 Ejemplo de flujo con `curl`

### 1️⃣ Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
-H "Content-Type: application/json" \
-d '{"username":"admin@example.com","password":"123456"}'

```

2️⃣ Acceso a un recurso protegido
```bash
curl -H "Authorization: Bearer $TOKEN" \
http://localhost:8080/api/v1/secure/ping

```

3️⃣ Refrescar token
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
-d '{"refreshToken":"..."}'

```
---
## 🔑 Generar claves RSA

```bash
openssl genpkey -algorithm RSA -out rsa-private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -pubout -in rsa-private.pem -out rsa-public.pem
```
Colocar en:

```bash
src/main/resources/keys/
```
---
## 🔁 HMAC ↔ RSA

RSA (recomendado)

```bash
security.jwt.algorithm: RSA
```

HMAC

```bash
security.jwt.algorithm: HMAC
security.jwt.secret: ${JWT_SECRET_BASE64}
```
---
## 👮 Filtros del sistema

| Filtro                  | Propósito                |
| ----------------------- | ------------------------ |
| NimbusJwtTokenProvider  | Firma + validación JWT   |
| JwtAuthorizationFilter  | Verifica firma + claims  |
| LoginRateLimitingFilter | Previene brute-force     |
| SecurityHeadersFilter   | Defensa XSS, HSTS, CSP   |
| CorrelationIdFilter     | Añade `X-Correlation-ID` |
| AuthNoCacheFilter       | Bloquea cache de tokens  |

---
## ⚖️ Matriz Roles / Scopes

| Rol        | Scopes         |
| ---------- | -------------- |
| ROLE_ADMIN | `*`            |
| ROLE_USER  | `profile:read` |
| ROLE_DEV   | bypass         |

---
## 🧩 Integración en otros microservicios
#### 1️⃣ Añadir dependencia
#### 2️⃣ Configurar RSA/HMAC
#### 3️⃣ Implementar UserAccountGateway
#### 4️⃣ (Opcional) Implementar ScopePolicy
#### 5️⃣ Proteger endpoints con @PreAuthorize
#### 6️⃣ Usar TestSecurityConfig en tests
---
## 🧩 Cómo usar esta plantilla en tu proyecto
1. Crear un nuevo repositorio usando
“Use this template”
2. Cambiar groupId / packages
3. Configurar claves:
    . dev → RSA demo
    . test → in-memory
    . prod → keystore / KMS / Secrets
4. Implementar UserAccountGateway
5. (Opcional) Implementar ScopePolicy
6. Proteger endpoints con:
 
 ```bash
@PreAuthorize("hasAuthority('SCOPE_profile:read')")
 ```
7. Integrarlo con API Gateway
8. Añadir tus casos de uso (application layer)
9. Extender roles/scopes según tu dominio
---
## 📘 Swagger UI

```bash
http://localhost:8080/swagger-ui/index.html
```
---
## 📦 Stack Técnico

| Componente     | Tecnología                       |
| -------------- | -------------------------------- |
| Lenguaje       | Java 21                          |
| Framework      | Spring Boot 3.4.x                |
| Seguridad      | Spring Security 6.x              |
| JWT            | **Nimbus JOSE + JWT**            |
| DB             | H2, MySQL, PostgreSQL            |
| Observabilidad | Prometheus                       |
| Testing        | JUnit 5, Mockito, Testcontainers |
| CI/CD          | GitHub Actions                   |
---
## ⚙️ Perfiles disponibles

| Perfil   | Descripción                                | Claves / Configuración                         |
| -------- | ------------------------------------------ | ---------------------------------------------- |
| **dev**  | Desarrollo. BD H2/MySQL. RSA de prueba.    | `keys/dev-public.pem` / `keys/dev-private.pem` |
| **test** | Tests unitarios/integración.               | Claves efímeras in-memory                      |
| **prod** | Entornos corporativos. Seguridad estricta. | Keystore / Secrets / KMS                       |

### 🔍 Descripción detallada

#### dev

- Usa claves RSA incluidas en src/main/resources/keys

- Permite registro (/auth/register)

- Menos restricciones (útil para desarrollo local)

#### test

- Claves generadas al vuelo

- TestSecurityConfig desactiva filtros innecesarios

- Todos los tests de Nimbus se ejecutan con claves in-memory

#### prod

- NO utiliza claves empaquetadas

Requiere claves externas mediante:

- Keystore JKS/PKCS12

- Vault / AWS KMS / Azure KeyVault / GCP Secrets

- Variables de entorno seguras (HMAC)
---

## 🧪 Tests y Calidad (Quality Gate)
| Tipo de Test    | Objetivo                                       | Framework / Técnica                     |
| --------------- | ---------------------------------------------- | --------------------------------------- |
| **Unit**        | TokenProvider, Nimbus, filtros, handlers       | JUnit 5 + Mockito                       |
| **Slice Tests** | Validación del AuthController sin servidor     | `@WebMvcTest` + Spring Security Test    |
| **Integración** | Flujo Login → Secure → Refresh completo        | `@SpringBootTest` + H2 / Testcontainers |
| **Config**      | SecurityConfig, métricas, filtros, propiedades | Spring Test + Assertions                |

### 📊 Calidad

- Cobertura mínima recomendada: ≥70% (JaCoCo)

- Checkstyle + Spotless: Formato consistente y limpio

- Static Analysis (opcional): SonarCloud / Semgrep

### CI/CD:

- Build

- Tests

- Cobertura

- Linting

- Docker build
---
## 🛠️ Ejecución
Dev
```bash
mvn spring-boot:run -Dspring.profiles.active=dev
```

Prod
```bash
java -jar spring-security-template.jar --spring.profiles.active=prod

```
---
## 🏗️ Requerimientos de despliegue

- Java 21+
- Docker 24+
- HTTPS obligatorio
- Claves RSA externas (prod)
- Vault / AWS KMS / KeyVault (opcional)

### Variables críticas:

- JWT_PRIVATE_KEY_PATH
- JWT_PUBLIC_KEY_PATH
- SPRING_PROFILES_ACTIVE
- JWT_SECRET_BASE64 (HMAC)
---
## 📝 Licencia

MIT © 2025 Lanny Rivero




