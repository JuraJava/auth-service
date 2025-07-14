FROM postgres:16.3
COPY init.sql /docker-entrypoint-initdb.d/init.sql
FROM openjdk:17-jdk-slim
COPY target/authService-0.0.1-SNAPSHOT.jar app.jar
ENTRYPOINT ["java", "-jar", "app.jar"]

