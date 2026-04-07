package com.github.brane08.service.webflux.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.server.session.WebSessionManager;
import reactor.core.publisher.Mono;

import java.security.interfaces.RSAPublicKey;

@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
public class Client2SecurityConfig {

    @Bean
    public SecurityWebFilterChain filterChain(ServerHttpSecurity http) {
        return http.csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(ae -> ae.anyExchange().authenticated())
                .oauth2ResourceServer(ors -> ors.jwt(Customizer.withDefaults()))
                .build();
    }

    @Bean
    public WebSessionManager webSessionManager() {
        return exchange -> Mono.empty();
    }

    @Bean
    ReactiveJwtDecoder jwtDecoder(@Value("${gateway.issuer-uri}") String issuerUri,
                                  @Value("${spring.security.oauth2.resourceserver.jwt.public-key-location}") Resource keyLocation) throws Exception {
        RSAPublicKey publicKey = (RSAPublicKey) RsaKeyConverters.x509().convert(keyLocation.getInputStream());
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withPublicKey(publicKey).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuerUri));
        return decoder;
    }
}
