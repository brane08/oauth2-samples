package com.github.brane08.academy.staticauthserver;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

import java.util.UUID;

//@SpringBootTest
class StaticAuthServerApplicationTests {

	@Test
	void contextLoads() {
		System.out.println(UUID.randomUUID().toString());
	}

}
