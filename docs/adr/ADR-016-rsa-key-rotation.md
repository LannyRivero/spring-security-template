# ADR-016 — Circuit Breakers y Resilience4j (Preparación futura)
📅 Fecha: 2025-11-17  
📁 Estado: Planificado

---

## 🎯 Contexto

Este proyecto de seguridad sirve como núcleo común de autenticación para múltiples microservicios.  
En entornos corporativos es común que:

- El servicio de seguridad llame a otros servicios (futuros módulos de usuarios, permisos, auditorías)
- Esos servicios puedan fallar temporalmente
- Picos de tráfico causen degradación
- Fallos en un servicio propaguen fallos al resto del sistema

Para evitar esto, las arquitecturas modernas usan:

- **Circuit Breakers**
- **Bulkheads**
- **Rate Limiters**
- **Timeouts**
- **Fallbacks**

Spring Boot integra Resilience4j de manera natural.

---

## 🧠 Decisión

No implementar Resilience4j dentro de este módulo todavía, pero preparar la arquitectura para que pueda usarse fácilmente cuando:

- Se agreguen microservicios dependientes  
- Se use un UserService externo  
- Se use un PermissionService externo  
- Se externalice la gestión de scopes/roles  

Actualmente, el template **funciona completamente aislado**, pero debe estar listo para ser un cliente resiliente de otros servicios.

---

## ✔ Razones principales

### 1️⃣ Evitar sobrecarga inicial  
El template no necesita aún llamadas externas.

### 2️⃣ Evitar acoplamiento innecesario  
El módulo de seguridad debe mantenerse **ligero**.

### 3️⃣ Preparar evolución futura  
Cuando exista una red de microservicios, se activará Resilience4j.

---

## 🧩 Alternativas consideradas

### 1. Implementar Resilience4j ahora  
✗ Añade complejidad  
✗ No hay dependencias aún  
✗ Más código y configuración innecesaria  

### 2. No documentarlo  
✗ Mala práctica  
✗ Reduce madurez del proyecto  

---

## 📌 Consecuencias

### Positivas
- El template sigue siendo ligero  
- Se documenta el roadmap  
- Arquitectura preparada para escalar  

### Negativas
- No hay protecciones de resiliencia hasta que se implementen módulos externos  

---

## 📤 Resultado

La arquitectura se documenta oficialmente como **compatible con Resilience4j**, pero se implementará cuando aparezcan microservicios dependientes.

