package com.github.brane08.oauth2.sso;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class SsoGatewayApplication {

	static {
		System.setProperty("com.sun.net.ssl.checkRevocation", "false");
		System.setProperty("jdk.internal.httpclient.disableHostnameVerification", "true");
//		System.setProperty("javax.net.debug", "all");
	}

	public static void main(String[] args) {
		SpringApplication.run(SsoGatewayApplication.class, args);
	}

}
