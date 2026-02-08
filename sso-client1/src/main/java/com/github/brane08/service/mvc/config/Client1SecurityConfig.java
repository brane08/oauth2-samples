package com.github.brane08.service.mvc.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

@Configuration(proxyBeanMethods = false)
@EnableWebSecurity
public class Client1SecurityConfig {

    private static final String[] STATIC_PATTERNS = new String[]{"/**/*.js", "/**/*.css"};

    @Bean
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        http.sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(ahr -> ahr.requestMatchers(STATIC_PATTERNS).permitAll().anyRequest().authenticated())
                .oauth2ResourceServer(ors -> ors.jwt(Customizer.withDefaults()));
        return http.build();
    }
}