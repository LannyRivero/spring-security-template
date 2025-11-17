# ADR-009 — InMemoryProviders en Perfil Dev
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado

---

## 🎯 Contexto

Durante el desarrollo local se necesita:

- Rapidez  
- Simplicidad  
- Claves cargadas automáticamente  
- Blacklist en memoria  
- Sin dependencias externas  
- Pruebas interactivas fáciles  

Pero este comportamiento NO debe activarse en producción.

---

## 🧠 Decisión

En el perfil `dev` se usan implementaciones **in-memory** para acelerar el desarrollo:

- InMemoryTokenBlacklistGateway  
- InMemoryRoleProvider  
- InMemoryScopePolicy  
- Claves RSA desde classpath  
- H2/MySQL local  

---

## ✔ Razones principales

### 1. Elimina fricción en desarrollo
El proyecto inicia inmediatamente con:

- claves precargadas  
- roles por defecto  
- scopes predefinidos  
- usuarios iniciales (si se desea)

### 2. Minimiza dependencias externas
Sin Redis  
Sin Vault  
Sin PostgreSQL  
Sin keystores

### 3. Evita sobre-configuración
Ideal para laptops, clases o talleres.

---

## 🧩 Alternativas consideradas

### 1. Usar Redis en local  
✗ Aumenta complejidad  
✗ No aporta valor en dev  

### 2. Usar BD real para roles/scopes  
✗ Más lento  
✗ No necesario  

### 3. Cargar claves desde filesystem  
✗ Innecesario en dev  
✗ Añade fricción  

---

## 📌 Consecuencias

### Positivas
- Experiencia dev muy fluida  
- Fácil onboarding  
- Rápido inicio de proyectos  
- Tests reproducibles  

### Negativas
- No apto para producción  
- Debe estar claramente separado por perfiles  

---

## 📤 Resultado

En `application-dev.yml`:

- Blacklist in-memory  
- Keys desde classpath  
- Roles base  
- ScopePolicy básica  

El perfil dev queda optimizado para productividad.

