package com.github.brane08.oauth2.server.config;

import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;
import com.github.brane08.oauth2.server.filters.SsoCookieAuthenticationFilter;
import com.github.brane08.oauth2.server.repository.AppUserRepository;
import com.github.brane08.oauth2.server.service.LocalUserDetailsService;
import com.github.brane08.oauth2.server.web.SsoAuthenticationProvider;
import com.github.brane08.oauth2.server.web.utils.RequestUtils;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.jackson.OAuth2AuthorizationServerJacksonModule;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.time.Duration;
import java.util.List;

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
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http,
                                                                      SecurityContextRepository contextRepository,
                                                                      RequestCache requestCache,
                                                                      SsoCookieAuthenticationFilter cookieFilter,
                                                                      SsoAuthenticationProvider ssoAuthProvider,
                                                                      UserDetailsService userDetailsService,
                                                                      AuthenticationEntryPoint customeAuthenticationEntrypoint) throws Exception {
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
                .userDetailsService(userDetailsService)
				.exceptionHandling((exceptions) -> exceptions
						.authenticationEntryPoint(customeAuthenticationEntrypoint)
				)
				.formLogin(AbstractHttpConfigurer::disable)
				.httpBasic(AbstractHttpConfigurer::disable)
				.cors(Customizer.withDefaults());
		http.addFilterBefore(cookieFilter, AnonymousAuthenticationFilter.class);
		// @formatter:on
        return http.build();
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE + 1)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http,
                                                          SecurityContextRepository contextRepository,
                                                          RequestCache requestCache,
                                                          SsoCookieAuthenticationFilter cookieFilter,
                                                          SsoAuthenticationProvider ssoAuthProvider) throws Exception {
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
				.requestCache(c -> c.requestCache(requestCache))
				.cors(Customizer.withDefaults());
		http.addFilterAfter(cookieFilter, AnonymousAuthenticationFilter.class);
		// @formatter:on
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService(AppUserRepository userRepository) {
        return new LocalUserDetailsService(userRepository);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource(
            @Value("${sas.jwt-signing-key-file:${user.dir}/../certs/jwt-signing-key.json}") String signingKeyFile) {
        RSAKey rsaKey = loadOrCreateSigningKey(Path.of(signingKeyFile));
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    private static RSAKey loadOrCreateSigningKey(Path keyPath) {
        try {
            if (Files.exists(keyPath)) {
                RSAKey rsaKey = RSAKey.parse(Files.readString(keyPath));
                LOG.info("Loaded persisted JWT signing key from {}", keyPath.toAbsolutePath());
                return rsaKey;
            }
            KeyPair keyPair = generateRsaKey();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
            RSAKey rsaKey = new RSAKey.Builder(publicKey).privateKey(privateKey).keyID("sas-jwt-key-id").build();
            if (keyPath.getParent() != null) {
                Files.createDirectories(keyPath.getParent());
            }
            Files.writeString(keyPath, rsaKey.toJSONString());
            try {
                Files.setPosixFilePermissions(keyPath, PosixFilePermissions.fromString("rw-------"));
            } catch (UnsupportedOperationException ignored) {
                // non-POSIX filesystem; skip permission tightening
            }
            LOG.warn("Generated new JWT signing key and persisted it to {}. " +
                    "Keep this file secret and back it up - losing it invalidates all outstanding tokens.",
                    keyPath.toAbsolutePath());
            return rsaKey;
        } catch (IOException | ParseException ex) {
            throw new IllegalStateException("Unable to load or create JWT signing key at " + keyPath, ex);
        }
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings(@Value("${sas.issuer}") String issuer) {
        return AuthorizationServerSettings.builder().issuer(issuer).build();
    }

    @Bean
    OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                return;
            }
            var principal = context.getPrincipal();
            // Only the username goes in the claim - principal.getPrincipal() is a Spring
            // Security User object whose toString()/serialization includes the password hash.
            context.getClaims().claim("user", principal.getName());
        };
    }

    @Bean
    JwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    // Scoped to only ssoAuthProvider - deliberately NOT the ambient global AuthenticationManager
    // that Spring Security auto-assembles from every AuthenticationProvider bean in the context.
    // SsoAuthenticationProvider.supports() claims any UsernamePasswordAuthenticationToken and
    // never checks credentials, so sharing it with a future password-based provider would let
    // it silently authenticate real login attempts without a password check.
    @Bean
    AuthenticationManager ssoCookieAuthenticationManager(SsoAuthenticationProvider ssoAuthProvider) {
        return new ProviderManager(ssoAuthProvider);
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

    // Rotates the session ID on successful pre-authentication so a session ID an attacker
    // planted before the SSO cookie was validated cannot be ridden in as the authenticated user.
    @Bean
    SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new ChangeSessionIdAuthenticationStrategy();
    }

    @Bean
    RequestCache requestCache() {
        return new SkipUrlHttpRequestCache();
    }

    @Bean
    SsoAuthenticationProvider ssoAuthProvider(UserDetailsService userDetailsService) {
        return new SsoAuthenticationProvider(userDetailsService);
    }

    @Bean
    SsoCookieAuthenticationFilter cookieFilter(AuthenticationManager authenticationManager,
                                               SecurityContextRepository contextRepository,
                                               SessionAuthenticationStrategy sessionAuthenticationStrategy,
                                               AuthenticationSuccessHandler successHandler,
                                               RequestCache requestCache,
                                               @Value("${sas.gateway-url}") String gatewayBaseUrl,
                                               @Value("${sas.use-redirect-in-filter}") boolean useRedirectInFilter) {
        return new SsoCookieAuthenticationFilter(authenticationManager, contextRepository, sessionAuthenticationStrategy,
                successHandler, requestCache,
                staticResourcesMatcher, publicPathMatcher, oauth2ProtectedMatcher, gatewayBaseUrl, useRedirectInFilter);
    }

    @Bean("securityObjectMapper")
    public ObjectMapper securityObjectMapper() {
        ClassLoader classLoader = JdbcAuthServerConfig.class.getClassLoader();
        return JsonMapper.builder()
                .addModules(SecurityJacksonModules.getModules(classLoader))
                .addModule(new OAuth2AuthorizationServerJacksonModule())
                .build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration strictConfig = new CorsConfiguration();
        strictConfig.addAllowedOriginPattern("https://*.example.local:8078");
        strictConfig.addAllowedOriginPattern("http://*.example.local:8040");
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
            LOG.debug("Authentication entrypoint called for uri: {}", request.getRequestURI());
            if (accept != null && accept.contains("text/html")) {
                int retryCount = RequestUtils.parseSsoRetryCount(request);
                if (retryCount >= RequestUtils.MAX_SSO_REDIRECT_ATTEMPTS) {
                    LOG.warn("SSO redirect loop detected after {} attempts for uri: {}", retryCount, request.getRequestURI());
                    response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"sso_loop_detected\",\"message\":\"Unable to establish SSO session after multiple attempts\"}");
                    return;
                }
                LOG.debug("Authentication entrypoint handling html request, redirect to gateway base url");
                String redirectUrl = gatewayBaseUrl + "?sso_continue=" + (retryCount + 1);
                response.setStatus(HttpServletResponse.SC_FOUND);
                response.setHeader("Location", redirectUrl);
            } else {
                LOG.debug("Authentication entrypoint handling non-html request, send unauthorized error");
                response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"unauthorized\",\"message\":\"Authentication required\"}");
            }
        };
    }
}
