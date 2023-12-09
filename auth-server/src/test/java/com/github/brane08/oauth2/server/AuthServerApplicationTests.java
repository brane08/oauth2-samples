package com.github.brane08.oauth2.server;

import com.github.brane08.oauth2.server.config.AuthServerConfig;
import org.junit.jupiter.api.Test;

class AuthServerApplicationTests {

	@Test
	void contextLoads() {
		AuthServerConfig config = new AuthServerConfig();
		System.out.println("Default password: " + config.passwordEncoder().encode("password"));
	}

}
