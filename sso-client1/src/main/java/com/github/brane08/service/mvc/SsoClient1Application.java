package com.github.brane08.service.mvc;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.servlet.UserDetailsServiceAutoConfiguration;

@SpringBootApplication(exclude = {UserDetailsServiceAutoConfiguration.class})
public class SsoClient1Application {

	public static void main(String[] args) {
		SpringApplication.run(SsoClient1Application.class, args);
	}

}
