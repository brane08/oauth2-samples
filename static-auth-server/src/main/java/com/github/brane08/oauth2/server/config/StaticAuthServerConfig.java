package com.github.brane08.oauth2.server.config;

import com.github.brane08.oauth2.server.filters.JwtCookieFilter;
import com.github.brane08.oauth2.server.services.CookieAwareUserDetailsService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
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
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class StaticAuthServerConfig {

	private static final Logger LOG = LoggerFactory.getLogger(StaticAuthServerConfig.class);

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
		final OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
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
			.requestCache(c -> c.requestCache(requestCache))
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/.well-known/**", "/error").permitAll()
				.anyRequest().authenticated()
			)
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
			.formLogin(form -> form
				.loginPage("/login").loginProcessingUrl("/login").permitAll()
			)
			.securityContext(sc -> sc.securityContextRepository(contextRepository))
			.requestCache(c -> c.requestCache(requestCache));
		http.addFilterBefore(cookieFilter, UsernamePasswordAuthenticationFilter.class);
		// @formatter:on
		return http.build();
	}

	@Bean
	public RegisteredClientRepository registeredClientRepository() {
		RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
				.clientId("8d0342a6-d045-434a-a5a3-2ad4976a07aa")
				.clientSecret("{noop}secret")
				.redirectUri("http://localhost:8078/login/oauth2/code/static-oidc")
				.redirectUri("http://localhost:8078/oauth2/code/static-oidc")
				.redirectUri("http://localhost:8078/authorized")
				.postLogoutRedirectUri("http://localhost:8078/logout")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
				.build();

		return new InMemoryRegisteredClientRepository(oidcClient);
	}

	@Bean
	public UserDetailsService userDetailsService(PasswordEncoder passwordEncoder) {
		UserDetailsService existingService = new InMemoryUserDetailsManager(
				User.withUsername("user").password(passwordEncoder.encode("password")).roles("USER").build(),
				User.withUsername("user1").password(passwordEncoder.encode("password")).roles("USER").build(),
				User.withUsername("user2").password(passwordEncoder.encode("password")).roles("USER").build(),
				User.withUsername("bob").password(passwordEncoder.encode("secret")).roles("USER").build()
		);
		return new CookieAwareUserDetailsService(existingService, passwordEncoder);
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
			if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
				context.getClaims().expiresAt(Instant.now().plus(Duration.ofHours(8)));
			}
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
	public AuthenticationSuccessHandler authenticationSuccessHandler(RequestCache requestCache) {
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

	@Bean
	public RedisSerializer<Object> springSessionDefaultRedisSerializer(JsonMapper mapper) {
		return new GenericJacksonJsonRedisSerializer(mapper);
	}
}
