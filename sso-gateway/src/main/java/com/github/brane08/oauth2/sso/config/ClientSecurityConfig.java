package com.github.brane08.oauth2.sso.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;

@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
public class ClientSecurityConfig {

	@Bean
	public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
		// @formatter:off
		var csrfRepo = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
		csrfRepo.setCookiePath("/");
        http.csrf(csrf -> csrf
				.csrfTokenRepository(csrfRepo))
			.authorizeExchange(ae -> ae
				.pathMatchers("/actuator/**", "/assets/**", "/favicon.ico").permitAll()
				.pathMatchers("/login", "/logout", "/oauth2/**").permitAll()
				.pathMatchers("/about", "/home", "default.html").permitAll()
				.anyExchange().authenticated())
			.oauth2Login(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}
}
