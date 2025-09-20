package com.github.brane08.oauth2.sso.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.web.server.adapter.ForwardedHeaderTransformer;

import java.net.URI;
import java.util.List;

@Configuration(proxyBeanMethods = false)
@EnableWebFluxSecurity
public class ClientSecurityConfig {

	@Bean
	public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
		var requestCache = new WebSessionServerRequestCache();
		var contextRepo = new WebSessionServerSecurityContextRepository();
		var csrfRepo = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
		csrfRepo.setCookiePath("/");
		var successHandler = new RedirectServerAuthenticationSuccessHandler();
		successHandler.setRequestCache(requestCache);
		successHandler.setLocation(URI.create("/")); // fallback if no saved request
		// @formatter:off
        http
			.csrf(csrf -> csrf.csrfTokenRepository(csrfRepo))
			.securityContextRepository(contextRepo)
			.requestCache(rc -> rc.requestCache(requestCache))
			.authorizeExchange(ae -> ae
				.pathMatchers("/actuator/**", "/assets/**", "/favicon.ico").permitAll()
				.pathMatchers("/login", "/logout", "/oauth2/**").permitAll()
				.pathMatchers("/about", "/home", "default.html").permitAll()
				.anyExchange().authenticated())
			.oauth2Login(o2l -> o2l.authenticationSuccessHandler(successHandler));
		// @formatter:on
		return http.build();
	}

	@Bean("securityObjectMapper")
	public ObjectMapper securityObjectMapper() {
		ObjectMapper objectMapper = new ObjectMapper();
		ClassLoader classLoader = ClientSecurityConfig.class.getClassLoader();
		List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
		objectMapper.registerModules(securityModules);
		objectMapper.registerModule(new OAuth2ClientJackson2Module());
		return objectMapper;
	}

	@Bean
	ForwardedHeaderTransformer forwardedHeaderTransformer() {
		return new ForwardedHeaderTransformer();
	}

	@Bean
	public RedisSerializer<Object> springSessionDefaultRedisSerializer(@Qualifier("securityObjectMapper") ObjectMapper securityObjectMapper) {
		return new GenericJackson2JsonRedisSerializer(securityObjectMapper);
	}
}
