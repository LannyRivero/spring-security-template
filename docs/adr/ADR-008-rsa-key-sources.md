# ADR-008 – Fuentes de claves RSA (classpath, filesystem, keystore)

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## Contexto

Las claves RSA privadas y públicas utilizadas para firmar y validar tokens deben:

- Ser fáciles de gestionar en dev/test.
- Ser seguras en producción.
- Integrarse con distintos mecanismos (keystore, archivos, KMS, etc.).

## Decisión

Soportar múltiples fuentes de claves RSA mediante distintos `RsaKeyProvider`:

- **Classpath (resources/keys)** → principalmente dev.
- **Filesystem** → contenedores y despliegues clásicos.
- **Keystore (JKS/PKCS12)** → producción recomendada.
- Preparar la integración futura con KMS / Secret Managers.

## Alternativas consideradas

1. **Solo classpath**
   - ✔ Muy fácil en dev.
   - ✖ Inaceptable para producción (claves empaquetadas en el artefacto).

2. **Solo filesystem**
   - ✔ Común en servidores tradicionales.
   - ✖ Menos conveniente en entornos cloud/Kubernetes.

3. **Solo keystore**
   - ✔ Seguro en producción.
   - ✖ Complejo e innecesario para entornos locales y de prueba.

## Justificación técnica

- Distintas organizaciones y entornos usan mecanismos diferentes para gestionar claves.
- Separar esto vía `RsaKeyProvider` permite adaptar la fuente de claves a cada contexto sin tocar el dominio ni los casos de uso.

## Consecuencias

**Positivas:**

- Alta flexibilidad de despliegue (local, Docker, Kubernetes, on-prem).
- Buenas prácticas de seguridad en producción (no empaquetar claves).
- Claridad de responsabilidades (infraestructura maneja las claves).

**Negativas:**

- Aumento del número de clases de infraestructura.
- Necesidad de documentación clara para cada modo de carga de claves.
