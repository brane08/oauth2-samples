# syntax=docker/dockerfile:1
FROM maven:3.9-eclipse-temurin-25 AS build
WORKDIR /workspace

COPY pom.xml .
COPY auth-common-jdbc auth-common-jdbc
COPY oauth2-server oauth2-server
COPY sso-gateway sso-gateway
COPY sso-gateway-mvc sso-gateway-mvc
COPY sso-client-common sso-client-common
COPY sso-client1 sso-client1
COPY sso-client2 sso-client2
COPY sso-client3 sso-client3

ARG MODULE
RUN mvn -q -pl ${MODULE} -am -DskipTests package

FROM eclipse-temurin:25-jre AS runtime
ARG MODULE
WORKDIR /app
COPY --from=build /workspace/${MODULE}/target/*.jar app.jar
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
