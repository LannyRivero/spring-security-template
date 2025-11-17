# ADR-016 — Rotación automática de claves RSA

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## 📌 Contexto
Las claves RSA deben rotarse periódicamente para cumplir requisitos OWASP, PCI y NIST.

## 🏆 Decisión
Implementar rotación:

- Soporte a múltiples claves simultáneas  
- Uso del claim `"kid"`  
- Keystore versionado  
- Carga dinámica desde KeyProvider

## 🎯 Motivaciones
- Seguridad a largo plazo  
- Prevención de compromisos  
- Compatibilidad con Gateways que esperan `kid`  
- Mejora de prácticas DevSecOps

## 🔄 Alternativas consideradas
- ❌ Una sola clave fija → no cumple estándares  
- ❌ Rotación manual → propenso a errores humanos

## 📌 Consecuencias
- Se mantiene un pool de claves públicas  
- Requiere actualización del KeyProvider  
- Tokens antiguos siguen validándose mientras la clave siga activa
