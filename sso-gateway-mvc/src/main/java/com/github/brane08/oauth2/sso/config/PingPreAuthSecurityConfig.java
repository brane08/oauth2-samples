package com.github.brane08.oauth2.sso.config;

import com.github.brane08.oauth2.sso.web.PingPreAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.web.context.SecurityContextRepository;

@Configuration(proxyBeanMethods = false)
@Profile("ping-preauth")
public class PingPreAuthSecurityConfig {

    @Bean
    public PingPreAuthenticationFilter pingPreAuthenticationFilter(SecurityContextRepository securityContextRepository) {
        return new PingPreAuthenticationFilter(securityContextRepository);
    }
}
