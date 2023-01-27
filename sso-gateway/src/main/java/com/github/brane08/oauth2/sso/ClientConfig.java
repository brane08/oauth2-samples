package com.github.brane08.oauth2.sso;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;

@Configuration
public class ClientConfig {

	@Bean
	public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
		return http.authorizeExchange().pathMatchers("/about").permitAll()
				.anyExchange().authenticated().and()
				.oauth2Login().and()
				.csrf().csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse()).and()
				.build();
	}
}
