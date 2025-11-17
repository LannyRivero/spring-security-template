# ADR-010 — Observabilidad con Prometheus
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado

---

## 🎯 Contexto

En sistemas distribuidos (microservicios) es imprescindible contar con:

- Métricas en tiempo real  
- Detección temprana de fallos  
- Trazabilidad  
- Dashboards en Grafana  
- Alertas automáticas  

Spring Boot Actuator expone métricas básicas, pero no incluye:

- Métricas específicas de autenticación  
- Contadores por intentos de login  
- Métricas por error 401/403  
- Latencia del SecurityFilterChain  

El proyecto necesita observabilidad avanzada desde el día 0.

---

## 🧠 Decisión

Se implementa un **AuthMetricsService** que expone métricas personalizadas en Prometheus:

### Métricas incluidas

| Nombre | Tipo | Descripción |
|--------|------|-------------|
| `auth_login_attempts_total` | Counter | Intentos de login |
| `auth_login_failures_total` | Counter | Fallos de login |
| `auth_tokens_created_total` | Counter | Tokens emitidos |
| `auth_tokens_invalid_total` | Counter | Tokens inválidos |
| `auth_tokens_expired_total` | Counter | Tokens expirados |

Además:

- Integración con Micrometer  
- Endpoint `/actuator/prometheus` habilitado  
- MDC enriquecido con Correlation-ID  

---

## ✔ Razones principales

### 1. Facilidad de integración en monitorización corporativa  
Prometheus + Grafana es estándar.

### 2. Seguridad observable  
Sin métricas, ataques de login pasan desapercibidos.

### 3. Preparación para autoscaling  
Permite detectar:

- picos de CPU  
- latencia del servicio  
- uso intensivo del login

---

## 🧩 Alternativas consideradas

### 1. Logs únicamente  
✗ No escalable  
✗ No apto para dashboards  

### 2. Métricas solo de Actuator  
✗ Insuficiente para auth  

### 3. NewRelic/AppDynamics  
✗ De pago  
✗ No siempre disponibles  

---

## 📌 Consecuencias

### Positivas
- Dashboards listos  
- Alertas configurables  
- Métricas de seguridad reales  

### Negativas
- Ligero overhead de recolección  

---

## 📤 Resultado

El microservicio expone métricas listas para Prometheus/Grafana y prepara al ecosistema para autoscaling y operaciones enterprise.

