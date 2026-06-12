FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn dependency:go-offline -q
COPY src ./src
RUN mvn clean package -DskipTests -q

FROM openjdk:25-ea-slim
RUN apt update && apt upgrade -y && apt install nmap -y
COPY --from=build /app/target/*.jar chausSec-backend.jar
ENTRYPOINT ["java", "-jar", "chausSec-backend.jar"]
