# 🛡️ Spring Security Template

Plantilla **Spring Boot 3.4.x + Java 21** con **autenticación y autorización JWT (RSA/HMAC)**, lista para integrarse como módulo base en proyectos de producción.

---

## 🎯 Objetivo

Ofrecer una **base profesional, segura y desacoplada**, aplicando:
- Clean Architecture + DDD  
- Spring Security 6 modular  
- JWT Access + Refresh Tokens  
- Roles y Scopes (RBAC + ABAC)  
- Testing, observabilidad y CI/CD  

---

## 🧱 Arquitectura (Clean Architecture)

```bash
application.auth
├── command → Casos de uso (LoginCommand, RefreshCommand)
├── port.in/out → Interfaces (AuthUseCase, TokenProvider, etc.)
├── result → Resultados (JwtResult, MeResult)
└── service → Implementaciones (AuthUseCaseImpl)
domain.model
├── User, Role, Scope, UserStatus
└── exception.UserLockedException
infrastructure
├── jwt → Implementaciones JWT (Jjwt, Nimbus)
├── security.filter → Filtros (Jwt, Headers, RateLimiter, etc.)
├── security.handler → Manejadores JSON (401, 403)
├── config → OpenAPI, CORS, Properties
└── persistence → Adaptadores de persistencia
web.auth
├── controller → Controladores REST
└── dto → DTOs (AuthRequest, AuthResponse, RefreshRequest, etc.)
```

---

## 🔐 Endpoints principales

| Método | Endpoint | Descripción | Público |
|--------|-----------|-------------|----------|
| `POST` | `/api/v1/auth/login` | Autentica usuario y emite Access/Refresh Token | ✅ |
| `POST` | `/api/v1/auth/refresh` | Genera nuevo Access Token | ✅ |
| `POST` | `/api/v1/auth/register` | Registra usuario (solo modo dev) | ✅ |
| `GET`  | `/api/v1/auth/me` | Devuelve datos del usuario actual | 🔒 |
| `GET`  | `/api/v1/secure/ping` | Endpoint protegido de ejemplo | 🔒 |
| `GET`  | `/actuator/health` | Healthcheck | ✅ |

---

## 🧩 Ejemplo de flujo con `curl`

### 1️⃣ Login
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "username": "admin@example.com",
    "password": "123456"
  }'
```
➡️ Devuelve:

```bash
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI...",
  "expiresAt": "2025-11-10T14:00:00Z"
}
```

2️⃣ Acceso a un recurso protegido
```bash
curl -X GET http://localhost:8080/api/v1/secure/ping \
  -H "Authorization: Bearer eyJhbGciOi..."
```

3️⃣ Refrescar token
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "eyJhbGciOi..."}'
```

⚙️ Perfiles disponibles

| Perfil   | Descripción                          | Claves                                         |
| -------- | ------------------------------------ | ---------------------------------------------- |
| **dev**  | Ejecuta con H2/MySQL + RSA demo keys | `keys/dev-public.pem` / `keys/dev-private.pem` |
| **test** | Usado para tests con claves efímeras | InMemory                                       |
| **prod** | Claves desde keystore o KMS          | Variables de entorno o Secret Manager          |



📘 Swagger UI
Disponible en:
```bash
👉 http://localhost:8080/swagger-ui/index.html
```

Usa el botón Authorize → Bearer Token para probar endpoints protegidos.
---

🧪 Tests y Calidad

| Tipo        | Objetivo                         | Framework              |
| ----------- | -------------------------------- | ---------------------- |
| Unit        | TokenProvider, filtros, handlers | JUnit 5 + Mockito      |
| Slice       | AuthController (Web layer)       | `@WebMvcTest`          |
| Integración | Flujo login → refresh → secure   | `@SpringBootTest` + H2 |


-  Cobertura: ≥70% (JaCoCo)
-  Checkstyle + Spotless: enforce style rules
-  CI/CD: GitHub Actions (build + test + cobertura + docker build)
---

🧰 Stack Técnico
| Componente    | Tecnología                         |
| ------------- | ---------------------------------- |
| Lenguaje      | Java 21                            |
| Framework     | Spring Boot 3.4.x                  |
| Seguridad     | Spring Security 6.x                |
| Autenticación | JWT (RSA / HMAC)                   |
| Documentación | Springdoc OpenAPI 3                |
| Testing       | JUnit 5 + Mockito + Testcontainers |
| Calidad       | JaCoCo, Checkstyle, Spotless       |
| DevOps        | Docker, GitHub Actions             |

---

⚙️ Ejecución local
```bash
java -jar target/spring-security-template.jar
```
---

📑 Licencia

MIT © 2025 Lanny Rivero Canino

