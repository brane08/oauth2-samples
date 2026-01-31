package com.github.brane08.oauth2.sso.config;

import com.github.brane08.oauth2.sso.web.SsoCookieTransformationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.jackson.SecurityJacksonModules;
import org.springframework.security.oauth2.client.jackson.OAuth2ClientJacksonModule;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.server.adapter.ForwardedHeaderTransformer;
import tools.jackson.databind.json.JsonMapper;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class ClientSecurityConfig {
    private final RequestMatcher staticResourcesMatcher;

    public ClientSecurityConfig(RequestMatcher staticResourcesMatcher) {
        this.staticResourcesMatcher = staticResourcesMatcher;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, RequestCache requestCache,
                                           JwtDecoder jwtDecoder) {
        var contextRepo = new HttpSessionSecurityContextRepository();
        var csrfRepo = CookieCsrfTokenRepository.withHttpOnlyFalse();
        csrfRepo.setCookiePath("/");
        var successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
        successHandler.setRequestCache(requestCache);
        successHandler.setDefaultTargetUrl("/");
        successHandler.setAlwaysUseDefaultTargetUrl(false); // fallback if no saved request
        // @formatter:off
        http
            .cors(Customizer.withDefaults())
            .csrf(csrf -> csrf.csrfTokenRepository(csrfRepo))
            .securityContext(context -> context.securityContextRepository(contextRepo))
            .requestCache(rc -> rc.requestCache(requestCache))
            .addFilterBefore(new SsoCookieTransformationFilter(), AnonymousAuthenticationFilter.class)
            .authorizeHttpRequests(ae -> ae
                    .requestMatchers("/actuator/**", "/logout", "/oauth2/**","/about", "/home", "/default.html").permitAll()
                    .requestMatchers(staticResourcesMatcher).permitAll()
                    .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                    .anyRequest().authenticated())
            .oauth2Login(o2l -> o2l.successHandler(successHandler))
            .oauth2Client(Customizer.withDefaults())
            .oauth2ResourceServer(o2r -> o2r.jwt(jwt -> jwt.decoder(jwtDecoder)));
        // @formatter:on
        return http.build();
    }

    @Bean
    public RequestCache requestCache() {
        var cache = new HttpSessionRequestCache();
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
    JwtDecoder jwtDecoder() {
        return JwtDecoders.fromIssuerLocation("https://auth.example.com:8077");
    }
}
