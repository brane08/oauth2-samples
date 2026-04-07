package com.github.brane08.oauth2.sso.config;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.brane08.oauth2.server.repository.AppUserRepository;
import com.github.brane08.oauth2.server.service.LocalUserDetailsService;
import com.github.brane08.oauth2.server.web.SsoAuthenticationProvider;
import com.github.brane08.oauth2.sso.client.CookiePathAuthEntryPoint;
import com.github.brane08.oauth2.sso.client.TokenMintService;
import com.github.brane08.oauth2.sso.web.SsoCookieTransformationFilter;
import com.github.brane08.oauth2.sso.web.SsoJwtTransformationFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.jackson2.OAuth2ClientJackson2Module;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.filter.CorsFilter;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;

@Configuration
@EnableWebSecurity
public class ClientSecurityConfig {
    private final RequestMatcher staticResourcesMatcher;

    public ClientSecurityConfig(RequestMatcher staticResourcesMatcher) {
        this.staticResourcesMatcher = staticResourcesMatcher;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http,
                                           RequestCache requestCache,
                                           SecurityContextRepository contextRepository,
                                           SsoAuthenticationProvider authenticationProvider,
                                           JwtDecoder jwtDecoder,
                                           SsoCookieTransformationFilter ssoFilter,
                                           SsoJwtTransformationFilter ssoJwtFilter,
                                           OAuth2AuthorizedClientService authorizedClientService,
                                           ClientRegistrationRepository registrationRepository,
                                           AuthenticationEntryPoint customEntryPoint) throws Exception {
        var csrfRepo = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfRepo.setCookiePath("/");
        // @formatter:off
        http
            .cors(Customizer.withDefaults())
            .csrf(csrf -> csrf
                    .csrfTokenRepository(csrfRepo)
                    .ignoringRequestMatchers("/mvc/**", "/flux/**", "/vaadin/**", "/actuator/**"))
            .authenticationProvider(authenticationProvider)
            .addFilterAfter(ssoFilter, CorsFilter.class)
            .addFilterBefore(ssoJwtFilter, UsernamePasswordAuthenticationFilter.class)
            .securityContext(context -> context.securityContextRepository(contextRepository))
            .requestCache(rc -> rc.requestCache(requestCache))
//            .addFilterBefore(new SsoCookieTransformationFilter(), AnonymousAuthenticationFilter.class)
            .authorizeHttpRequests(ae -> ae
                    .requestMatchers("/actuator/**", "/logout", "/oauth2/**", "/about", "/home", "/default.html").permitAll()
                    .requestMatchers(staticResourcesMatcher).permitAll()
                    .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                    .anyRequest().authenticated())
            .oauth2Login(AbstractHttpConfigurer::disable)
            .oauth2Client(o2c -> o2c
                    .authorizedClientService(authorizedClientService)
                    .clientRegistrationRepository(registrationRepository))
            .exceptionHandling(eh -> eh
                    .authenticationEntryPoint(customEntryPoint));
        // @formatter:on
        return http.build();
    }

    @Bean
    public RequestCache requestCache() {
        return new HttpSessionRequestCache();
    }

    @Bean
    AuthenticationSuccessHandler successHandler(RequestCache requestCache) {
        var successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setRequestCache(requestCache);
        successHandler.setDefaultTargetUrl("/");
        successHandler.setUseReferer(true);
        successHandler.setAlwaysUseDefaultTargetUrl(false);
        return successHandler;
    }

    @Bean
    SecurityContextRepository contextRepository() {
        return new HttpSessionSecurityContextRepository();
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
    public SsoCookieTransformationFilter ssoCookieFilter() {
        return new SsoCookieTransformationFilter();
    }

    @Bean
    JwtDecoder jwtDecoder(RestTemplate restTemplate) {
        return NimbusJwtDecoder.withIssuerLocation("https://auth.example.com:8077").restOperations(restTemplate).build();
    }

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    @Bean
    public UserDetailsService userDetailsService(AppUserRepository userRepository) {
        return new LocalUserDetailsService(userRepository);
    }

    @Bean
    SsoAuthenticationProvider ssoAuthProvider(UserDetailsService userDetailsService) {
        return new SsoAuthenticationProvider(userDetailsService);
    }

    @Bean
    SsoJwtTransformationFilter jwtTransformationFilter(AuthenticationManager authenticationManager,
                                                       SecurityContextRepository contextRepository,
                                                       RequestCache requestCache,
                                                       RequestMatcher staticResourcesMatcher,
                                                       ClientRegistrationRepository clientRepo,
                                                       OAuth2AuthorizedClientService authorizedClientService,
                                                       TokenMintService mintService) {
        return new SsoJwtTransformationFilter(authenticationManager, contextRepository, requestCache,
                staticResourcesMatcher, clientRepo, authorizedClientService, mintService);
    }

    @Bean
    AuthenticationEntryPoint customEntryPoint(@Value("${gateway.base-url}") String baseUrl) {
        return new CookiePathAuthEntryPoint(baseUrl);
    }
}
