# 🔐 Autenticación

La autenticación se basa en **JWT (Access + Refresh)** firmados con **Nimbus JOSE + JWT**, siguiendo buenas prácticas OWASP.

---

## 🔑 Flujo de Autenticación

1. El usuario envía credenciales a `/api/v1/auth/login`
2. Se validan en `AuthUseCaseImpl`
3. Nimbus genera:
   - Access Token (corto plazo)
   - Refresh Token (medio plazo)
4. El cliente almacena ambos tokens de forma segura.
5. Para acceder a recursos protegidos se envía:

Authorization: Bearer <access-token>


---

## 🧠 Validaciones importantes

- El usuario debe estar **activo** (`UserStatus.ACTIVE`)
- No estar **bloqueado** ni **eliminado**
- Contraseña válida (BCrypt)
- Credenciales incorrectas → excepción `InvalidCredentialsException`

---

## 🎟 Tokens generados

### Access Token
- De uso rápido
- No debe guardarse en cookies
- Expira rápido

### Refresh Token
- Permite obtener un nuevo access token
- *NO debe reutilizarse* → Refresh Token Rotation

---

## 🔄 Refresh Token Rotation

Implementado siguiendo prácticas modernas de seguridad:

- Cada refresh token se usa **una sola vez**
- El anterior se mete en **blacklist**
- Si un token se reutiliza → posible ataque → se rechaza

---

## 🧪 Tests relacionados

- `JwtUtilsTest`
- `NimbusJwtTokenProviderTest`
- `JwtUtilsHmacTest`
- `AuthControllerTest`
