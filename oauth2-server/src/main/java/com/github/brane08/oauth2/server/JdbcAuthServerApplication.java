package com.github.brane08.oauth2.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;
import org.springframework.data.jdbc.repository.config.EnableJdbcRepositories;

@SpringBootApplication(exclude = {MongoAutoConfiguration.class, UserDetailsServiceAutoConfiguration.class})
@EnableJdbcRepositories(basePackages = {"com.github.brane08.oauth2.server.repository"})
public class JdbcAuthServerApplication {

    static {
        System.setProperty("com.sun.net.ssl.checkRevocation", "false");
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        System.setProperty("javax.net.ssl.trustStore", "/Users/bhushanr/incubator/samples/oauth2-samples/certs/truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
    }

    public static void main(String[] args) {
        SpringApplication.run(JdbcAuthServerApplication.class, args);
    }

}
