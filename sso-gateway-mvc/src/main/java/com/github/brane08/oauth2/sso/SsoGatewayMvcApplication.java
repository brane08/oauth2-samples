package com.github.brane08.oauth2.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.security.autoconfigure.UserDetailsServiceAutoConfiguration;

@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class SsoGatewayMvcApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsoGatewayMvcApplication.class, args);
    }

}
