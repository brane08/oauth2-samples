package com.github.brane08.service.webflux.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.session.WebSessionManager;
import reactor.core.publisher.Mono;

@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
public class Client2SecurityConfig {

	@Bean
	public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
		return http.csrf(ServerHttpSecurity.CsrfSpec::disable)
				.authorizeExchange(ae -> ae.anyExchange().authenticated())
				.oauth2ResourceServer(ors -> ors.jwt(Customizer.withDefaults()))
				.build();
	}

	@Bean
	public WebSessionManager webSessionManager() {
		return exchange -> Mono.empty();
	}
}
