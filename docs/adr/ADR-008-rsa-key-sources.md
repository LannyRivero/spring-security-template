# ADR-008 — Fuentes de Claves RSA (classpath, filesystem, keystore)
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado

---

## 🎯 Contexto

El sistema soporta JWT firmados con RSA.  
Para firmar y validar se requieren claves:

- `privateKey` → firma  
- `publicKey` → validación  

Diferentes entornos requieren diferentes estrategias:

| Entorno | Necesidad |
|---------|-----------|
| dev     | simplicidad, claves incluidas |
| test    | claves efímeras in-memory |
| prod    | claves seguras en keystores o KMS |

El proyecto debe soportar TODAS estas opciones sin acoplarse a ninguna.

---

## 🧠 Decisión

Se definen **3 KeyProviders**, seleccionables vía configuración:

### 1. **ClasspathRsaKeyProvider**
- Carga claves desde `src/main/resources/keys`
- Ideal para `dev`

### 2. **FileSystemRsaKeyProvider**
- Carga claves desde rutas absolutas en filesystem
- Ideal para contenedores Docker no seguros

### 3. **KeystoreRsaKeyProvider**
- Carga claves desde JKS/PKCS12
- Compatible con:
  - AWS KMS
  - Azure KeyVault
  - GCP Secret Manager
- Recomendado para `prod`

---

## ✔ Razones principales

### 1. Flexibilidad total  
Cualquier microservicio puede escoger su proveedor.

### 2. Seguridad real en producción  
Los keystores evitan almacenar claves en recursos.

### 3. Testing sencillo  
Los tests cargan claves en memoria sin depender del SO.

---

## 🧩 Alternativas consideradas

### 1. Solo claves en classpath  
✗ Inseguro en prod  
✗ No cumple estándares corporativos  

### 2. Solo filesystem  
✗ Inconveniente en CI/CD  
✗ No funciona en AWS Lambda, CloudRun  

### 3. Solo keystore  
✗ Overkill en dev/test  
✗ Más complejo  

---

## 📌 Consecuencias

### Positivas
- Seguridad adaptable por entorno  
- Claves externas en producción  
- Tests controlados  
- Deployment flexible  

### Negativas
- Más código  
- Configuración más avanzada  

---

## 📤 Resultado

El template queda preparado para cualquier tipo de despliegue:

- Local  
- Docker  
- Kubernetes  
- Cloud (AWS/Azure/GCP)

Y soporta migración futura a JWKS.

