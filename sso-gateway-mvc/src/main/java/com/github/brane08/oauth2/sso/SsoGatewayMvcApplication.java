package com.github.brane08.oauth2.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.mongo.MongoAutoConfiguration;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class, MongoAutoConfiguration.class})
public class SsoGatewayMvcApplication {

    static {
        System.setProperty("com.sun.net.ssl.checkRevocation", "false");
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
        System.setProperty("javax.net.ssl.trustStore", "/Users/bhushanr/incubator/samples/oauth2-samples/certs/truststore.jks");
        System.setProperty("javax.net.ssl.trustStorePassword", "changeit");
    }

    public static void main(String[] args) {
        SpringApplication.run(SsoGatewayMvcApplication.class, args);
    }

}
