# ADR-010 – Observabilidad con Prometheus

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## Contexto

La seguridad no solo debe implementarse, sino **monitorizarse**.  
Es necesario medir:

- Número de logins exitosos y fallidos.
- Tokens rechazados por firma / expiración / blacklist.
- Número de peticiones protegidas.
- Posibles patrones anómalos (brute force, abusos, etc.).

La mayoría de entornos modernos utilizan **Prometheus + Grafana** como stack de observabilidad.

## Decisión

Integrar la plantilla con **Prometheus** mediante:

- Un servicio de métricas (`AuthMetricsService`).
- Configuración de registro de métricas (`PrometheusConfigBean`).
- Exponer contadores y métricas clave vía Actuator / Micrometer.

## Alternativas consideradas

1. **Solo logs**
   - ✔ Fácil de implementar.
   - ✖ No ofrece métricas agregadas en tiempo real.
   - ✖ Más difícil de visualizar tendencias.

2. **Métricas internas sin Prometheus**
   - ✔ Menos dependencias.
   - ✖ Menor compatibilidad con entornos Kubernetes y cloud.

## Justificación técnica

- Prometheus es estándar de facto en infraestructuras cloud-native.
- La plantilla debe ser “listo para producción” no solo en seguridad, sino también en observabilidad.
- Las métricas permiten al equipo de operaciones detectar patrones de ataque y problemas antes de que escalen.

## Consecuencias

**Positivas:**

- Integración directa con Grafana / Kubernetes / Alertmanager.
- Mayor capacidad de auditoría y respuesta ante incidentes.
- Refuerza el carácter enterprise de la plantilla.

**Negativas:**

- Ligero aumento de complejidad en configuración.
- Necesidad de definir y mantener un conjunto coherente de métricas.
