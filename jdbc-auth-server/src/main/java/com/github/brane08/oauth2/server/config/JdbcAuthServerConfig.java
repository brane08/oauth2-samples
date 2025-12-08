package com.github.brane08.oauth2.server.config;

import com.github.brane08.oauth2.server.filters.JwtCookieFilter;
import com.github.brane08.oauth2.server.repository.AppUserRepository;
import com.github.brane08.oauth2.server.service.CookieAwareUserDetailsService;
import com.github.brane08.oauth2.server.service.LocalUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.serializer.GenericJacksonJsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializer;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import tools.jackson.databind.json.JsonMapper;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration(proxyBeanMethods = false)
public class JdbcAuthServerConfig {

	private static final Logger LOG = LoggerFactory.getLogger(JdbcAuthServerConfig.class);

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
																	  SecurityContextRepository contextRepository,
																	  RequestCache requestCache,
																	  JwtCookieFilter cookieFilter) {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
				new OAuth2AuthorizationServerConfigurer();

		// @formatter:off
		http
			.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.with(authorizationServerConfigurer, configurer -> configurer
				.oidc(Customizer.withDefaults())
				.tokenRevocationEndpoint(Customizer.withDefaults())
				.tokenIntrospectionEndpoint(Customizer.withDefaults())
			)
			.csrf(csrf -> csrf.ignoringRequestMatchers(authorizationServerConfigurer.getEndpointsMatcher()))
			.securityContext(sc -> sc.securityContextRepository(contextRepository))
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/.well-known/**", "/error").permitAll()
				.anyRequest().authenticated()
			)
			.requestCache(c -> c.requestCache(requestCache))
			.exceptionHandling((exceptions) -> exceptions
				.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"),
					new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
				)
			);
		http.addFilterBefore(cookieFilter, UsernamePasswordAuthenticationFilter.class);
		// @formatter:on
		return http.build();
	}

	// Default application chain (non-SAS endpoints)
	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE + 1)
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
														  SecurityContextRepository contextRepository,
														  RequestCache requestCache,
														  JwtCookieFilter cookieFilter) {
		// @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/.well-known/**", "/error","/login", "/css/**", "/js/**").permitAll()
				.anyRequest().authenticated()
			)
			.formLogin(Customizer.withDefaults())
			.securityContext(sc -> sc.securityContextRepository(contextRepository))
			.requestCache(c -> c.requestCache(requestCache))
			.addFilterBefore(cookieFilter, UsernamePasswordAuthenticationFilter.class);
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
	JwtCookieFilter cookieFilter(UserDetailsService userDetailsService, SecurityContextRepository contextRepository,
								 AuthenticationSuccessHandler successHandler) {
		return new JwtCookieFilter(userDetailsService, contextRepository, successHandler);
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
}
