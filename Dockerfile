# ==============================
# 🧩 Build Stage
# ==============================
FROM maven:3.9.9-eclipse-temurin-21 AS builder
WORKDIR /app

# Copiar pom y descargar dependencias
COPY pom.xml .
RUN mvn -q dependency:go-offline

# Copiar código fuente y compilar
COPY src ./src
RUN mvn -q clean package -DskipTests

# ==============================
# 🚀 Runtime Stage
# ==============================
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Copiar el jar generado
COPY --from=builder /app/target/*.jar app.jar

# Exponer puerto por defecto
EXPOSE 8080

# Ejecutar la aplicación
ENTRYPOINT ["java", "-jar", "app.jar"]
