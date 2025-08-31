package com.github.brane08.oauth2.server;

import com.github.brane08.oauth2.server.config.JdbcAuthServerConfig;
import org.junit.jupiter.api.Test;

class JdbcAuthServerApplicationTests {

	@Test
	void contextLoads() {
		JdbcAuthServerConfig config = new JdbcAuthServerConfig();
		System.out.println("Default password: " + config.passwordEncoder().encode("password"));
	}

}
