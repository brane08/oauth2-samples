package com.github.brane08.oauth2.sso.config;

import com.github.brane08.oauth2.sso.web.SsoCookieTransformationFilter;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.serializer.GenericJacksonJsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.client.jackson.OAuth2ClientJacksonModule;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoders;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.savedrequest.ServerRequestCache;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.server.adapter.ForwardedHeaderTransformer;
import tools.jackson.databind.json.JsonMapper;

import java.net.URI;

@Configuration
@EnableWebFluxSecurity
public class ClientSecurityConfig {

	private final ServerWebExchangeMatcher staticResourcesMatcher;

	public ClientSecurityConfig(ServerWebExchangeMatcher staticResourcesMatcher) {
		this.staticResourcesMatcher = staticResourcesMatcher;
	}

	@Bean
	public SecurityWebFilterChain filterChain(ServerHttpSecurity http, ServerRequestCache requestCache,
											  ReactiveJwtDecoder jwtDecoder) {
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
			.addFilterBefore(new SsoCookieTransformationFilter(), SecurityWebFiltersOrder.AUTHENTICATION)
			.authorizeExchange(ae -> ae
				.pathMatchers("/actuator/**", "/logout", "/oauth2/**","/about", "/home", "default.html").permitAll()
				.matchers(staticResourcesMatcher).permitAll()
				.pathMatchers(HttpMethod.OPTIONS, "/**").permitAll()
				.anyExchange().authenticated())
			.oauth2Login(o2l -> o2l.authenticationSuccessHandler(successHandler))
			.oauth2Client(Customizer.withDefaults())
			.oauth2ResourceServer(o2r -> o2r.jwt(jwt -> jwt.jwtDecoder(jwtDecoder)));
		// @formatter:on
		return http.build();
	}

	@Bean
	public ServerRequestCache requestCache() {
		var cache = new WebSessionServerRequestCache();
		cache.setSaveRequestMatcher(ServerWebExchangeMatchers.pathMatchers("/oauth2/", "/login/ouath2/"));
		return cache;
	}

	@Bean("securityObjectMapper")
	public JsonMapper securityObjectMapper() {
		ClassLoader classLoader = ClientSecurityConfig.class.getClassLoader();
		return JsonMapper.builder()
				.addModules(SecurityJacksonModules.getModules(classLoader))
				.addModules(new OAuth2ClientJacksonModule())
				.build();
	}

	@Bean
	ForwardedHeaderTransformer forwardedHeaderTransformer() {
		return new ForwardedHeaderTransformer();
	}

	@Bean
	public RedisSerializer<Object> springSessionDefaultRedisSerializer(@Qualifier("securityObjectMapper") JsonMapper securityObjectMapper) {
		return new GenericJacksonJsonRedisSerializer(securityObjectMapper);
	}

	@Bean
	ReactiveJwtDecoder jwtDecoder() {
		return ReactiveJwtDecoders.fromIssuerLocation("https://auth.example.com:8077");
	}
}
