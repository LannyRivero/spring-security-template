# 🔑 Gestión de Claves (Key Management)

Este proyecto permite usar claves desde:

✔ Classpath  
✔ FileSystem  
✔ Keystore (JKS/PKCS12)  
✔ External Vault / AWS KMS / GCP Secret Manager  

---

## 📦 Classpath (dev)

Colocar:

src/main/resources/keys/dev-private.pem
src/main/resources/keys/dev-public.pem


---

## 💾 FileSystem

En `application-prod.yml`:

```yaml
security.jwt.keyLocation: /opt/keys/prod-private.pem
```
---
## 🔐 Keystore (producción recomendada)

```yaml
security.jwt.keystore.location: classpath:jwt.jks
security.jwt.keystore.password: ${KEYSTORE_PASS}
```
---

## 🔄 Rotación de claves

- Las claves nuevas se usan para firmar tokens

- Las claves viejas validan tokens antiguos

- Expirados → se eliminan