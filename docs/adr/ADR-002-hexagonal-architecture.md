# ADR-002 — Arquitectura Hexagonal
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado  

---

## 🎯 Contexto

El proyecto debe funcionar como **plantilla enterprise**, extensible y reutilizable.  
La seguridad debe ser independiente del framework, de la capa web y de la persistencia.

Además, el template debe integrarse como módulo en:

- RenewSim  
- Buzón Inteligente  
- Microservicios futuros  

Esto exige baja dependencia y alta modularidad.

---

## 🧠 Decisión

Se adopta **Arquitectura Hexagonal (Ports & Adapters)** combinada con Clean Architecture.

---

## ✔ Razones principales

### 1. Separación total entre dominio y detalles
- TokenProvider no depende de Nimbus  
- UserAccountGateway no depende de JPA  
- Filtros no contienen lógica de negocio  

### 2. Permite sustituir tecnologías fácilmente
- Cambiar Nimbus → JJWT  
- Cambiar persistencia → Mongo, JPA, memoria  
- Cambiar filtros  
- Integrar OAuth2 Authorization Server

### 3. Facilita testing avanzado
- Tests unitarios sin Spring  
- Tests de integración por adaptadores  
- Tests de casos de uso sin web

### 4. Patrón estándar en arquitectura empresarial

---

## 🧩 Alternativas consideradas

### 1. Arquitectura en capas clásica (controllers → services → repositories)  
✗ Acoplada  
✗ No reutilizable  
✗ Difícil de testear

### 2. Microkernel / plugin architecture  
✗ Overkill  
✗ No aporta ventajas aquí

---

## 📌 Consecuencias

### Positivas
- Plantilla profesional
- Muy fácil de extender
- Permite mocking/ports clean
- Mejor mantenimiento a largo plazo
- Testing más rápido y modular

### Negativas
- Más archivos / verbosidad
- Más disciplina arquitectónica

---

## 📤 Resultado

Estructura aprobada:

application/
domain/
infrastructure/
web/
