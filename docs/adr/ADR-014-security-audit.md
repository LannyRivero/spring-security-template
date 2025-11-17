# ADR-014 — Canary Releases en despliegues futuros
📅 Fecha: 2025-11-17  
📁 Estado: Planificado

---

## 🎯 Contexto

La plantilla está diseñada para producción real:

- Kubernetes  
- CI/CD  
- Escalado horizontal  

Muchos equipos requieren **Canary Releases**, es decir:  
Desplegar una versión nueva a un % pequeño de usuarios y observar métricas antes de un rollout total.

En el futuro, el módulo de seguridad podría requerir:

- Nuevos filtros  
- Cambios en tokens  
- Cambios en KeyProviders  
- Cambios en scopes  

y un error podría impactar a toda la organización.

---

## 🧠 Decisión

Se documenta la compatibilidad futura con **Canary Releases**, aunque no se implementa en código todavía.

### Estrategia futura recomendada:

1. Usar labels de versión en pods:  
   `version=v1`, `version=v2`

2. Configurar Ingress/Gateway con:  
   - tráfico dividido por %  
   - reglas por header `X-Canary`  
   - decisiones del LoadBalancer  

3. Observar métricas del ADR-010:  
   - login success/failure  
   - tokens invalid  
   - latencia  

---

## ✔ Razones principales

### 1. Zero-downtime upgrades  
Seguridad crítica → no puede fallar.

### 2. Despliegues seguros  
Un bug grave se detecta antes de afectar a todos los usuarios.

### 3. Integración cloud-native  
Compatible con:

- Istio  
- Nginx Ingress  
- AWS ALB  
- Traefik  

---

## 🧩 Alternativas consideradas

### Blue-Green Deployment  
✗ Duplica costos  
✗ No prueba la feature con tráfico real parcial  

### Rolling Update clásico  
✗ Si hay bug, afecta a todos  

---

## 📌 Consecuencias

### Positivas
- Preparación para producción real  
- Plantilla alineada con microservicios modernos  

### Negativas
- Necesaria infraestructura cloud para implementarlo  

---

## 📤 Resultado

La arquitectura queda oficialmente preparada para estrategias Canary en despliegues avanzados.

