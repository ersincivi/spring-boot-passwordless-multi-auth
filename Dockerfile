# --------------------
# STAGE 1: BUILD — JDK 25 + Maven
# --------------------
FROM maven:3.9-eclipse-temurin-25 AS builder

WORKDIR /build

COPY pom.xml .
COPY src ./src

RUN mvn clean package -DskipTests

# --------------------
# STAGE 2: RUNTIME — JRE 25 only
# --------------------
FROM eclipse-temurin:25-jre

WORKDIR /app

COPY --from=builder /build/target/spring-boot-passwordless-multi-auth-0.0.1-SNAPSHOT.jar app.jar

EXPOSE 8585

CMD ["java", "-jar", "app.jar"]
