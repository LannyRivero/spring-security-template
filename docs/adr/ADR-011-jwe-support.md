# ADR-011 — Soporte opcional para JWE (JSON Web Encryption)

**Estado:** Propuesto  
**Fecha:** 2025-03-01

## 📌 Contexto
El proyecto utiliza actualmente JWS (JSON Web Signature) para firmar JWT.  
Sin embargo, algunos entornos corporativos manejan información sensible en los tokens (claims internos, PII, datos de privilegios) y requieren **encriptación** además de firma.

JWE, soportado de forma nativa por Nimbus JOSE + JWT, permite cifrar el contenido del token.

## 🏆 Decisión
Incorporar un módulo opcional JWE basado en:

- Algoritmo de clave: `RSA-OAEP`  
- Algoritmo de contenido: `A256GCM`

Los tokens podrán ser emitidos como:

- **JWS** (solo firma, modo por defecto)
- **JWE** (firma + cifrado, configurable)

## 🎯 Motivaciones
- Protección total de claims sensibles  
- Cumplimiento GDPR / ISO / PCI  
- Integración nativa con Nimbus  
- Es compatible con OAuth2 y OIDC

## 🔄 Alternativas consideradas
- ❌ Mantener solo JWS → expone claims sensibles en entornos críticos  
- ❌ Cifrado manual por aplicación → complejo y no estándar  
- ❌ Encriptar parcialmente claims → no asegura integridad

## 📌 Consecuencias
- Introduce configuración adicional  
- Ligera sobrecarga de CPU al cifrar/descifrar  
- Aumenta significativamente la seguridad en entornos regulados
