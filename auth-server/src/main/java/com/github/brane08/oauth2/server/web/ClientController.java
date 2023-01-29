package com.github.brane08.oauth2.server.web;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.brane08.oauth2.server.domain.CustomRegisteredClient;
import com.github.brane08.oauth2.server.repository.CustomRegisteredClientRepository;
import com.github.brane08.oauth2.server.repository.jdbc.JdbcRegisteredClientRepository;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.jdbc.core.JdbcAggregateTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/registered-clients")
public class ClientController {

    private final RegisteredClientRepository clientRepository;
    private final CustomRegisteredClientRepository customClientRepository;
    private final PasswordEncoder encoder;

    public ClientController(@Qualifier("securityObjectMapper") ObjectMapper securityObjectMapper,
                            CustomRegisteredClientRepository customClientRepository,
                            JdbcAggregateTemplate aggregateTemplate, PasswordEncoder encoder) {
        this.customClientRepository = customClientRepository;
        this.clientRepository = new JdbcRegisteredClientRepository(securityObjectMapper, customClientRepository,
                aggregateTemplate);
        this.encoder = encoder;
    }

    @GetMapping
    public ResponseEntity<List<CustomRegisteredClient>> listAll() {
        return ResponseEntity.accepted().body(customClientRepository.findAll());
    }

    @GetMapping("new")
    public ResponseEntity<CustomRegisteredClient> newClient() {
        TokenSettings tokenSettings = TokenSettings.builder().accessTokenTimeToLive(Duration.ofDays(1L))
                .authorizationCodeTimeToLive(Duration.ofMinutes(10L)).refreshTokenTimeToLive(Duration.ofDays(30L))
                .build();
        String clientId = UUID.randomUUID().toString();
        RegisteredClient registeredClient = RegisteredClient.withId(clientId)
                .clientId(clientId)
                .clientName("custom-sso-client")
                .clientSecret(encoder.encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientIdIssuedAt(Instant.now())
                .clientSecretExpiresAt(Instant.now().plus(Duration.ofDays(365 * 2)))
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:8080/login/oauth2/code/client-oidc")
                .redirectUri("http://localhost:8080/oauth2/code/client-oidc")
                .redirectUri("http://localhost:8080/callback")
                .redirectUri("http://localhost:8080/authorized")
                .redirectUri("http://localhost:8080/")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .tokenSettings(tokenSettings)
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
                .build();
        clientRepository.save(registeredClient);
        return ResponseEntity.noContent().build();
    }
}
