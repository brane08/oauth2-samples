package com.github.brane08.oauth2.server.repository.jdbc;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;
import com.github.brane08.oauth2.server.domain.CustomRegisteredClient;
import com.github.brane08.oauth2.server.repository.CustomRegisteredClientRepository;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.jdbc.core.JdbcAggregateTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public class JdbcRegisteredClientRepository implements RegisteredClientRepository {

	private static final Logger log = LoggerFactory.getLogger(JdbcRegisteredClientRepository.class);
	private static final TypeReference<Map<String, Object>> MAP_TYPE_REFERENCE = new TypeReference<>() {
	};
	private static final String DEFAULT_CLIENT_ID = "2e8347f2-ccac-4d03-bc2c-cc733ec4da10";

	private final CustomRegisteredClientRepository clientRepository;
	private final JdbcAggregateTemplate aggregateTemplate;
	private final JsonMapper securityObjectMapper;
	private final PasswordEncoder encoder;

	public JdbcRegisteredClientRepository(@Qualifier("securityObjectMapper") JsonMapper securityObjectMapper,
										  CustomRegisteredClientRepository clientRepository,
										  JdbcAggregateTemplate aggregateTemplate, PasswordEncoder encoder) {
		Assert.notNull(clientRepository, "clientRepository cannot be null");
		this.securityObjectMapper = securityObjectMapper;
		this.clientRepository = clientRepository;
		this.aggregateTemplate = aggregateTemplate;
		this.encoder = encoder;
	}

	@PostConstruct
	public void checkAndSaveDefaultClient() {
		RegisteredClient defaultClient = findByClientId(DEFAULT_CLIENT_ID);
		if (defaultClient != null) {
			log.info("Default client found, skipping init");
			return;
		}

		TokenSettings tokenSettings = TokenSettings.builder().accessTokenTimeToLive(Duration.ofDays(1L))
				.authorizationCodeTimeToLive(Duration.ofMinutes(10L)).refreshTokenTimeToLive(Duration.ofDays(30L))
				.build();
		RegisteredClient registeredClient = RegisteredClient.withId(DEFAULT_CLIENT_ID)
				.clientId(DEFAULT_CLIENT_ID)
				.clientName("custom-sso-client")
				.clientSecret(encoder.encode("secret"))
				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
				.clientIdIssuedAt(Instant.now())
				.clientSecretExpiresAt(Instant.now().plus(Duration.ofDays(365 * 2)))
				.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
				.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
				.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
				.redirectUri("http://localhost:8078/login/oauth2/code/client-oidc")
				.redirectUri("http://localhost:8078/oauth2/code/client-oidc")
				.redirectUri("http://localhost:8078/callback")
				.redirectUri("http://localhost:8078/authorized")
				.redirectUri("http://localhost:8078/")
				.redirectUri("http://localhost:8077/login/oauth2/code/client-oidc")
				.redirectUri("http://localhost:8077/oauth2/code/client-oidc")
				.redirectUri("http://localhost:8077/callback")
				.redirectUri("http://localhost:8077/authorized")
				.redirectUri("http://localhost:8077/")
				.scope(OidcScopes.OPENID)
				.scope(OidcScopes.PROFILE)
				.scope(OidcScopes.EMAIL)
				.tokenSettings(tokenSettings)
				.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
				.build();
		this.save(registeredClient);
		log.info("Default client not found, added again with ID: {}", DEFAULT_CLIENT_ID);
	}

	@Override
	public void save(RegisteredClient registeredClient) {
		Assert.notNull(registeredClient, "registeredClient cannot be null");
		this.aggregateTemplate.insert(toEntity(registeredClient));
	}

	@Override
	public RegisteredClient findById(String id) {
		Assert.hasText(id, "id cannot be empty");
		return this.clientRepository.findById(id).map(this::toObject).orElse(null);
	}

	@Override
	public RegisteredClient findByClientId(String clientId) {
		Assert.hasText(clientId, "clientId cannot be empty");
		return this.clientRepository.findByClientId(clientId).map(this::toObject).orElse(null);
	}

	private RegisteredClient toObject(CustomRegisteredClient client) {
		Set<String> clientAuthenticationMethods = StringUtils.commaDelimitedListToSet(
				client.getClientAuthenticationMethods());
		Set<String> authorizationGrantTypes = StringUtils.commaDelimitedListToSet(
				client.getAuthorizationGrantTypes());
		Set<String> redirectUris = StringUtils.commaDelimitedListToSet(
				client.getRedirectUris());
		Set<String> clientScopes = StringUtils.commaDelimitedListToSet(
				client.getScopes());

		RegisteredClient.Builder builder = RegisteredClient.withId(client.getId())
				.clientId(client.getClientId())
				.clientIdIssuedAt(client.getClientIdIssuedAt())
				.clientSecret(client.getClientSecret())
				.clientSecretExpiresAt(client.getClientSecretExpiresAt())
				.clientName(client.getClientName())
				.clientAuthenticationMethods(authenticationMethods ->
						clientAuthenticationMethods.forEach(authenticationMethod ->
								authenticationMethods.add(resolveClientAuthenticationMethod(authenticationMethod))))
				.authorizationGrantTypes((grantTypes) ->
						authorizationGrantTypes.forEach(grantType ->
								grantTypes.add(resolveAuthorizationGrantType(grantType))))
				.redirectUris((uris) -> uris.addAll(redirectUris))
				.scopes((scopes) -> scopes.addAll(clientScopes));

		Map<String, Object> clientSettingsMap = parseMap(client.getClientSettings());
		builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());

		Map<String, Object> tokenSettingsMap = parseMap(client.getTokenSettings());
		builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build());

		return builder.build();
	}

	private CustomRegisteredClient toEntity(RegisteredClient registeredClient) {
		List<String> clientAuthenticationMethods = new ArrayList<>(registeredClient.getClientAuthenticationMethods().size());
		registeredClient.getClientAuthenticationMethods().forEach(clientAuthenticationMethod ->
				clientAuthenticationMethods.add(clientAuthenticationMethod.getValue()));

		List<String> authorizationGrantTypes = new ArrayList<>(registeredClient.getAuthorizationGrantTypes().size());
		registeredClient.getAuthorizationGrantTypes().forEach(authorizationGrantType ->
				authorizationGrantTypes.add(authorizationGrantType.getValue()));

		CustomRegisteredClient entity = new CustomRegisteredClient();
		entity.setId(registeredClient.getId());
		entity.setClientId(registeredClient.getClientId());
		entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
		entity.setClientSecret(registeredClient.getClientSecret());
		entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
		entity.setClientName(registeredClient.getClientName());
		entity.setClientAuthenticationMethods(StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
		entity.setAuthorizationGrantTypes(StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
		entity.setRedirectUris(StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
		entity.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));
		entity.setClientSettings(writeMap(registeredClient.getClientSettings().getSettings()));
		entity.setTokenSettings(writeMap(registeredClient.getTokenSettings().getSettings()));

		return entity;
	}

	private Map<String, Object> parseMap(String data) {
		try {
			return this.securityObjectMapper.readValue(data, MAP_TYPE_REFERENCE);
		} catch (Exception ex) {
			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}

	private String writeMap(Map<String, Object> data) {
		try {
			return this.securityObjectMapper.writeValueAsString(data);
		} catch (Exception ex) {
			throw new IllegalArgumentException(ex.getMessage(), ex);
		}
	}

	private static AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
		if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.AUTHORIZATION_CODE;
		} else if (AuthorizationGrantType.CLIENT_CREDENTIALS.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.CLIENT_CREDENTIALS;
		} else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
			return AuthorizationGrantType.REFRESH_TOKEN;
		}
		return new AuthorizationGrantType(authorizationGrantType);              // Custom authorization grant type
	}

	private static ClientAuthenticationMethod resolveClientAuthenticationMethod(String clientAuthenticationMethod) {
		if (ClientAuthenticationMethod.CLIENT_SECRET_BASIC.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
		} else if (ClientAuthenticationMethod.CLIENT_SECRET_POST.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.CLIENT_SECRET_POST;
		} else if (ClientAuthenticationMethod.NONE.getValue().equals(clientAuthenticationMethod)) {
			return ClientAuthenticationMethod.NONE;
		}
		return new ClientAuthenticationMethod(clientAuthenticationMethod);      // Custom client authentication method
	}
}