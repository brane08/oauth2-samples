package com.github.brane08.oauth2.sso.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;

@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
public class ClientSecurityConfig {

	@Bean
	public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
		// @formatter:off
		var requestCache = new WebSessionServerRequestCache();
		var contextRepo  = new WebSessionServerSecurityContextRepository();
		var csrfRepo = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
		csrfRepo.setCookiePath("/");
        http.csrf(csrf -> csrf
				.csrfTokenRepository(csrfRepo)
			)
			.securityContextRepository(contextRepo)
			.requestCache(rc -> rc.requestCache(requestCache))
			.authorizeExchange(ae -> ae
				.pathMatchers("/actuator/**", "/assets/**", "/favicon.ico").permitAll()
				.pathMatchers("/login", "/logout", "/oauth2/**").permitAll()
				.pathMatchers("/about", "/home", "default.html").permitAll()
				.anyExchange().authenticated())
			.oauth2Login(Customizer.withDefaults());
		// @formatter:on
		return http.build();
	}

	@Bean
	public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
		return new GenericJackson2JsonRedisSerializer();
	}
}
