package com.github.brane08.oauth2.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class StaticAuthServerApplication {

    static {
        System.setProperty("com.sun.net.ssl.checkRevocation", "false");
        System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
    }

    public static void main(String[] args) {
        SpringApplication.run(StaticAuthServerApplication.class, args);
    }

}
