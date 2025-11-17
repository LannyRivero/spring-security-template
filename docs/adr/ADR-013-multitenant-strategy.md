# ADR-013 — Estrategia de Caching y ETags
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado

---

## 🎯 Contexto

En APIs REST modernas, el caching mejora:

- Rendimiento
- Latencia
- Consumo de CPU
- Costos en cloud

Sin embargo, en un sistema de autenticación:

- Algunos endpoints **no deben cachearse**  
  (login, refresh, me)
- Otros sí pueden beneficiarse  
  (recursos públicos, endpoints estáticos)
- Las respuestas sensibles deben incluir headers de control

Se necesita una estrategia clara y segura.

---

## 🧠 Decisión

Se implementa una política dual:

### 1️⃣ **Endpoints de autenticación (auth/)**  
Cache **deshabilitado** mediante el filtro `AuthNoCacheFilter`:

Headers aplicados:

- `Cache-Control: no-store`
- `Pragma: no-cache`
- `Expires: 0`

### 2️⃣ **Endpoints públicos / estáticos**  
Caching opcional mediante:

- ETags (`If-None-Match`)
- Cache-Control configurable
- Long-lived caching para recursos estáticos

### 3️⃣ **Documentación OpenAPI**  
Los headers se reflejan en la documentación.

---

## ✔ Razones principales

### 1. Seguridad estricta (OWASP ASVS)  
Tokens nunca deben quedar en discos/snapshots/cache.

### 2. Mejor rendimiento en recursos públicos  
ETags reduce tráfico en:

- `/health`
- Documentación
- Recursos estáticos

### 3. Control granular  
Cada endpoint mantiene su política.

---

## 🧩 Alternativas consideradas

### No usar caching  
✗ Peor rendimiento  
✗ No aprovecha ETags  

### Usar caching global  
✗ Inseguro para autenticación  
✗ Riesgo de exposición de tokens  

---

## 📌 Consecuencias

### Positivas
- Seguridad reforzada  
- Rendimiento optimizado  
- Control fine-grained  

### Negativas
- Más configuración per-endpoint  

---

## 📤 Resultado

El sistema distingue claramente entre:

- endpoints que **no deben ser cacheados**
- endpoints que **pueden beneficiarse del caching**

Usando filtros, headers y ETags.

