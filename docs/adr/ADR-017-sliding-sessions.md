# ADR-017 — Política de Expiración de Tokens (TTL Strategy)
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado

---

## 🎯 Contexto

En un sistema basado en JWT firmados localmente, no existe un servidor de estado que mantenga sesiones.  
Por tanto, la expiración de tokens (TTL) es fundamental para:

- Evitar sesiones eternas  
- Reducir superficie de ataque  
- Limitar el impacto si un token se filtra  
- Controlar la rotación del refresh token  

Distintos entornos requieren distintas TTL.

---

## 🧠 Decisión

Se define una política de expiración flexible:

### 1️⃣ Access Token  
Uso: peticiones normales  
- **TTL recomendado: 15 minutos**  
- Reclamaciones obligatorias: `exp`, `iat`, `jti`

### 2️⃣ Refresh Token  
Uso: obtener nuevos access tokens  
- **TTL recomendado: 7 días**  
- Si la organización lo requiere → 30 días  
- Siempre firmado  
- Siempre en rotación (ADR-003)

### 3️⃣ Perfiles
- **dev** → Access 1h / Refresh 24h  
- **test** → Tokens muy cortos (5 min)  
- **prod** → Accesos cortos (15m) y refresh moderado (7d)

---

## ✔ Razones principales

### 1. Seguridad real  
Tokens largos aumentan riesgo.

### 2. Buen equilibrio entre seguridad y UX  
15 minutos es estándar en:

- Google  
- AWS  
- Azure  
- GitHub  

### 3. Compatible con Refresh Token Rotation  
TTL más largo requiere rotación para mantener seguridad.

---

## 🧩 Alternativas consideradas

### Tokens sin expiración  
✗ Inaceptable  
✗ Vulnerabilidad crítica  

### Access Tokens de varias horas  
✗ Riesgo alto en caso de robo  

### Refresh Tokens eternos  
✗ Rompen el modelo stateless  

---

## 📌 Consecuencias

### Positivas
- Seguridad fuerte y probada  
- UX mantenida  
- Plantilla alineada con estándares  

### Negativas
- Más llamadas al endpoint `/auth/refresh`  

---

## 📤 Resultado

El sistema usa una política de expiración clara, segura, configurable por entorno y alineada con el ADR-003 de Refresh Token Rotation.

