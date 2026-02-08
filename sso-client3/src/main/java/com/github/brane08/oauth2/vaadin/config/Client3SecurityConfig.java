package com.github.brane08.oauth2.vaadin.config;

import com.vaadin.flow.spring.security.VaadinSecurityConfigurer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class Client3SecurityConfig {

    private static final String[] STATIC_PATTERNS = new String[]{"/**/*.js", "/**/*.css"};

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        // @formatter:off
        http
            .sessionManagement(sm -> sm
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable)
            .headers(h -> h
                .frameOptions(fo -> fo.disable())
                .contentSecurityPolicy(csp -> csp.policyDirectives("upgrade-insecure-requests")))
            .authorizeHttpRequests(ahr -> ahr
                .requestMatchers("/vaadin/VAADIN/**", "/vaadin/vaadin/**", "/vaadin/images/**").permitAll()
                .requestMatchers(STATIC_PATTERNS).permitAll()
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(ors -> ors
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())));
        // @formatter:on
        // Apply Vaadin AFTER your rules, but WITHOUT auto auth config
        VaadinSecurityConfigurer conf = VaadinSecurityConfigurer.vaadin();
        conf.enableAuthorizedRequestsConfiguration(false);  // Skip its anyRequest()
        http.with(conf, Customizer.withDefaults());
        return http.build();
    }

    JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            List<GrantedAuthority> authorities = new ArrayList<>();

            // Extract from your nested "user.authorities" structure
            Map<String, Object> userClaim = jwt.getClaimAsMap("user");
            if (userClaim != null) {
                @SuppressWarnings("unchecked")
                List<Map<String, Object>> userAuthorities = (List<Map<String, Object>>) userClaim.get("authorities");
                if (userAuthorities != null) {
                    for (Map<String, Object> auth : userAuthorities) {
                        String role = (String) auth.get("role");
                        if (role != null) {
                            authorities.add(new SimpleGrantedAuthority("ROLE_" + role.toUpperCase()));
                        }
                    }
                }
            }

            // Fallback: add scopes too
            List<String> scopes = jwt.getClaimAsStringList("scope");
            if (scopes != null) {
                scopes.forEach(scope -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope)));
            }

            return authorities;
        });
        return converter;
    }
}