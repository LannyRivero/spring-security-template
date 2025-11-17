# ADR-011 — Futuro Soporte para JWE (Encrypted JWT)
📅 Fecha: 2025-11-17  
📁 Estado: Evaluación

---

## 🎯 Contexto

Actualmente se utiliza **JWS (firmado)** con JWT autocontenidos.  
Es el estándar para microservicios.

Sin embargo, en industrias como:

- banca  
- salud  
- gobiernos  
- defensa  

Puede requerirse **JWE (JSON Web Encryption)** para ocultar:

- datos sensibles  
- metadatos  
- claims ocultos  

Nimbus JOSE + JWT soporta JWE de forma nativa.

---

## 🧠 Decisión (actual)

**No implementar JWE todavía**, pero dejar:

- arquitectura lista  
- TokenProvider extensible  
- KeyProvider compatible  
- ADR documentado  

para una futura fase.

---

## ✔ Razones principales

### 1. JWE incrementa complejidad
- Doble operación: firmar + encriptar  
- Más claves  
- Más CPU  

### 2. No aporta valor al caso actual
Los tokens no contienen PII, solo metadatos seguros.

### 3. JWE complica interoperabilidad
Muchos gateways no soportan JWE.

---

## 🧩 Alternativas consideradas

### Implementar JWE desde el inicio  
✗ Overkill  
✗ Peor rendimiento  
✗ No requerido por el proyecto  

---

## 📌 Consecuencias

### Positivas
- Arquitectura lista para migrar  
- Decisión documentada  

### Negativas
- El equipo debe estar alerta si un partner requiere JWE  

---

## 📤 Resultado

El sistema continúa usando **JWS firmado**, pero está listo para activar JWE sin romper la arquitectura.

