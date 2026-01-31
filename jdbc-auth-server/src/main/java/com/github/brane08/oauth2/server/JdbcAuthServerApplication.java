package com.github.brane08.oauth2.server;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.webmvc.autoconfigure.error.ErrorMvcAutoConfiguration;

@SpringBootApplication(exclude = {ErrorMvcAutoConfiguration.class})
public class JdbcAuthServerApplication {

    public static void main(String[] args) {
        SpringApplication.run(JdbcAuthServerApplication.class, args);
    }

}
