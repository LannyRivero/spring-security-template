# ADR-012 — Integración opcional con OAuth2 Authorization Server

**Estado:** Planeado  
**Fecha:** 2025-03-01

## 📌 Contexto
La plantilla funciona como Authentication Provider local.  
Pero entornos corporativos usan herramientas externas como:

- Keycloak  
- Auth0  
- Okta  
- Azure AD  
- Spring Authorization Server  

Para habilitar SSO, MFA, social login y federación.

## 🏆 Decisión
Preparar adaptadores opcionales para delegar:

- Autenticación  
- Introspección  
- Rotación de tokens  
- Validación remota  

Manteniendo la lógica actual como fallback.

## 🎯 Motivaciones
- Integración transparente con ecosistemas enterprise  
- Roadmap natural hacia OAuth2/OIDC  
- Posibilidad de Single Sign-On  
- Mejor soporte para MFA y políticas corporativas

## 🔄 Alternativas consideradas
- ❌ Forzar OAuth2 desde el inicio → demasiado rígido  
- ❌ Autenticación local siempre → limita escalabilidad

## 📌 Consecuencias
- El template será usable tanto como IdP local como integración OAuth2  
- Añade complejidad opcional, no obligatoria
