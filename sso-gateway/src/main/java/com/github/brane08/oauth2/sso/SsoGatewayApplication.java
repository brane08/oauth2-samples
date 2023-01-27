package com.github.brane08.oauth2.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.reactive.ReactiveUserDetailsServiceAutoConfiguration;

@SpringBootApplication(exclude = {ReactiveUserDetailsServiceAutoConfiguration.class})
public class SsoGatewayApplication {

	public static void main(String[] args) {
		SpringApplication.run(SsoGatewayApplication.class, args);
	}

}
