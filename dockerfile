FROM openjdk:25-ea-slim

RUN apt update && apt upgrade -y
RUN apt install nmap -y

COPY target/*.jar chausSec-backend.jar

ENTRYPOINT [ "java", "-jar", "chausSec-backend.jar" ]

