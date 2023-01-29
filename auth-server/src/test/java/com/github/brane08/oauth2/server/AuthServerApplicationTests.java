package com.github.brane08.oauth2.server;

import com.github.brane08.oauth2.server.config.DefaultSecurityConfig;
import org.junit.jupiter.api.Test;

class AuthServerApplicationTests {

	@Test
	void contextLoads() {
		DefaultSecurityConfig config = new DefaultSecurityConfig();
		System.out.println("Default password: " + config.passwordEncoder().encode("password"));
	}

}
