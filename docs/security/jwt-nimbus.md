# 🔏 JWT con Nimbus JOSE + JWT

Este proyecto usa **Nimbus JOSE + JWT**, estándar en banca, fintech y sistemas de alta seguridad.

---

## 🚀 Ventajas sobre JJWT

| Característica | JJWT | Nimbus |
|----------------|------|--------|
| JOSE completo  | ❌ | ✔ |
| JWE (encriptación) | ❌ | ✔ |
| JWK/JWK Set | ❌ | ✔ |
| Uso empresarial | Medio | Alto |
| Integración OAuth2/OIDC | Media | Alta |

---

## 🧱 Firmas soportadas

### 🔐 RSA (recomendado)
- Firma asimétrica
- Uso en microservicios
- Compatible con Rotación de claves
- Recomendado para producción

### 🔑 HMAC
- Más simple
- Menos seguro
- Útil para desarrollo o sistemas pequeños

---

## 🔧 Claims incluidos

```json
{
  "sub": "user@example.com",
  "roles": ["ROLE_USER"],
  "scopes": ["profile:read"],
  "iat": 1710000000,
  "exp": 1710003600,
  "jti": "uuid",
  "iss": "spring-security-template"
}
```

## 🧪 Tests relacionados

- NimbusJwtTokenProviderTest

- JwtUtilsTest

- JwtUtilsHmacTest