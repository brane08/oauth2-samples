package com.github.brane08.oauth2.server.config;

import com.github.brane08.oauth2.server.filters.SsoCookieAuthenticationFilter;
import com.github.brane08.oauth2.server.repository.AppUserRepository;
import com.github.brane08.oauth2.server.service.CookieAwareUserDetailsService;
import com.github.brane08.oauth2.server.service.LocalUserDetailsService;
import com.github.brane08.oauth2.server.web.SsoAuthenticationProvider;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.serializer.GenericJacksonJsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.NoOpAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tools.jackson.databind.json.JsonMapper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.util.UUID;

@Configuration
public class JdbcAuthServerConfig {

	private static final Logger LOG = LoggerFactory.getLogger(JdbcAuthServerConfig.class);

	private final RequestMatcher staticResourcesMatcher;
	private final RequestMatcher publicPathMatcher;
	private final RequestMatcher oauth2ProtectedMatcher;

	public JdbcAuthServerConfig(RequestMatcher staticResourcesMatcher, RequestMatcher publicPathMatcher,
								RequestMatcher oauth2ProtectedMatcher) {
		this.staticResourcesMatcher = staticResourcesMatcher;
		this.publicPathMatcher = publicPathMatcher;
		this.oauth2ProtectedMatcher = oauth2ProtectedMatcher;
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
																	  SecurityContextRepository contextRepository,
																	  RequestCache requestCache,
																	  SsoCookieAuthenticationFilter cookieFilter,
																	  SsoAuthenticationProvider ssoAuthProvider) {
		final OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
		// @formatter:off
		http
				.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
				.with(authorizationServerConfigurer, configurer -> configurer
						.oidc(Customizer.withDefaults())
						.tokenRevocationEndpoint(Customizer.withDefaults())
						.tokenIntrospectionEndpoint(Customizer.withDefaults())
				)
				.csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(sm -> sm
						.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
				.securityContext(sc -> sc.securityContextRepository(contextRepository))
				.requestCache(c -> c.requestCache(requestCache))
				.authorizeHttpRequests((authorize) -> authorize
						.requestMatchers(staticResourcesMatcher).permitAll()
						.requestMatchers(publicPathMatcher).permitAll()
						.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
						.anyRequest().authenticated()
				)
				.authenticationProvider(ssoAuthProvider)
				.exceptionHandling((exceptions) -> exceptions
						.authenticationEntryPoint(new NoOpAuthenticationEntryPoint())
				)
				.formLogin(AbstractHttpConfigurer::disable)
				.httpBasic(AbstractHttpConfigurer::disable);
		http.addFilterAfter(cookieFilter, AnonymousAuthenticationFilter.class);
		// @formatter:on
		return http.build();
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
														  SecurityContextRepository contextRepository,
														  RequestCache requestCache,
														  SsoCookieAuthenticationFilter cookieFilter,
														  SsoAuthenticationProvider ssoAuthProvider) {
		// @formatter:off
		http
				.csrf(AbstractHttpConfigurer::disable)
				.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED))
				.authorizeHttpRequests((authorize) -> authorize
						.requestMatchers(staticResourcesMatcher).permitAll()
						.requestMatchers(publicPathMatcher).permitAll()
						.requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
						.anyRequest().authenticated()
				)
				.formLogin(AbstractHttpConfigurer::disable)
				.httpBasic(AbstractHttpConfigurer::disable)
				.authenticationProvider(ssoAuthProvider)
				.securityContext(sc -> sc.securityContextRepository(contextRepository))
				.requestCache(c -> c.requestCache(requestCache));
		http.addFilterAfter(cookieFilter, AnonymousAuthenticationFilter.class);
		// @formatter:on
		return http.build();
	}

	@Bean
	public UserDetailsService userDetailsService(AppUserRepository userRepository) {
		return new CookieAwareUserDetailsService(new LocalUserDetailsService(userRepository));
	}

	@Bean
	public JWKSource<SecurityContext> jwkSource() {
		KeyPair keyPair = generateRsaKey();
		RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
		RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
		RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID(UUID.randomUUID().toString()).build();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return new ImmutableJWKSet<>(jwkSet);
	}

	private static KeyPair generateRsaKey() {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.generateKeyPair();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
		return context -> {
			if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
				return;
			}
			var principal = context.getPrincipal();
			context.getClaims().claim("user", principal.getPrincipal());
		};
	}

	@Bean
	public JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
		return config.getAuthenticationManager();
	}

	@Bean
	AuthenticationSuccessHandler authenticationSuccessHandler(RequestCache requestCache) {
		var successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
		successHandler.setDefaultTargetUrl("/");
		successHandler.setAlwaysUseDefaultTargetUrl(false);
		successHandler.setRequestCache(requestCache);
		return successHandler;
	}

	@Bean
	SecurityContextRepository contextRepository() {
		return new HttpSessionSecurityContextRepository();
	}

	@Bean
	RequestCache requestCache() {
		return new SkipUrlHttpRequestCache();
	}

	@Bean
	SsoCookieAuthenticationFilter cookieFilter(AuthenticationManager authenticationManager,
											   SecurityContextRepository contextRepository,
											   AuthenticationSuccessHandler successHandler,
											   RequestCache requestCache,
											   @Value("${sas.gateway-url}") String gatewayBaseUrl) {
		return new SsoCookieAuthenticationFilter(authenticationManager, contextRepository, successHandler, requestCache,
				staticResourcesMatcher, publicPathMatcher, oauth2ProtectedMatcher, gatewayBaseUrl);
	}

	@Bean("securityObjectMapper")
	public JsonMapper securityObjectMapper() {
		ClassLoader classLoader = JdbcAuthServerConfig.class.getClassLoader();
		return JsonMapper.builder()
				.addModules(SecurityJacksonModules.getModules(classLoader))
				.addModules(new OAuth2AuthorizationServerJacksonModule())
				.build();
	}

	@Bean
	public RedisSerializer<Object> springSessionDefaultRedisSerializer(@Qualifier("securityObjectMapper") JsonMapper securityObjectMapper) {
		return new GenericJacksonJsonRedisSerializer(securityObjectMapper);
	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {
		CorsConfiguration strictConfig = new CorsConfiguration();
		strictConfig.addAllowedOriginPattern("https://*.example.com:8078");
		strictConfig.addAllowedOriginPattern("http://*.example.com:8040");
		strictConfig.setAllowCredentials(true);
		strictConfig.addAllowedMethod("POST");
		strictConfig.addAllowedMethod("GET");
		strictConfig.addAllowedMethod("OPTIONS");
		strictConfig.addAllowedMethod("HEAD");
		strictConfig.addAllowedHeader("*");
		strictConfig.setMaxAge(Duration.ofMinutes(30));
		CorsConfiguration lenientConfig = new CorsConfiguration();
		lenientConfig.addAllowedOriginPattern("*");
		lenientConfig.setAllowCredentials(false);
		lenientConfig.addAllowedMethod("GET");
		lenientConfig.addAllowedMethod("HEAD");
		lenientConfig.addAllowedMethod("OPTIONS");
		lenientConfig.addAllowedHeader("*");
		lenientConfig.setMaxAge(Duration.ofMinutes(60));
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/oauth2/**", strictConfig);
		source.registerCorsConfiguration("/userinfo", strictConfig);
		source.registerCorsConfiguration("/**/*.js", lenientConfig);
		source.registerCorsConfiguration("/**/*.css", lenientConfig);
		source.registerCorsConfiguration("/**/*.wasm", lenientConfig);
		source.registerCorsConfiguration("/**/*.map", lenientConfig);
		source.registerCorsConfiguration("/assets/**", lenientConfig);
		return source;
	}

	@Bean
	public AuthenticationEntryPoint customAuthenticationEntryPoint(@Value("${sas.gateway-url}") String gatewayBaseUrl) {
		return (request, response, authException) -> {
			String accept = request.getHeader("Accept");
			if (accept != null && accept.contains("text/html")) {
				response.sendRedirect(gatewayBaseUrl + request.getRequestURI() + (request.getQueryString() != null ? "?" + request.getQueryString() : ""));
			} else {
				response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
				response.setContentType("application/json");
				response.getWriter().write("{\"error\":\"unauthorized\",\"message\":\"Authentication required\"}");
			}
		};
	}
}
