package com.github.brane08.oauth2.sso.client;

import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.data.mongodb.core.query.Criteria;
import org.springframework.data.mongodb.core.query.Query;
import org.springframework.data.mongodb.core.query.Update;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.stereotype.Service;

@Service
public class MongoOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {

    private final MongoTemplate mongoTemplate;
    private final ClientRegistrationRepository clientRepo;
    private static final String COLLECTION = "oauth2_authorized_clients";

    public MongoOAuth2AuthorizedClientService(MongoTemplate mongoTemplate, ClientRegistrationRepository clientRepo) {
        this.mongoTemplate = mongoTemplate;
        this.clientRepo = clientRepo;
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        Query query = new Query(Criteria.where("registrationId").is(clientRegistrationId).and("principalName").is(principalName));
        return (T) toAuthorizedClient(mongoTemplate.find(query, MongoAuthorizedClient.class).stream().findFirst().orElse(null));
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        Query query = new Query(Criteria.where("registrationId").is(authorizedClient.getClientRegistration().getRegistrationId())
                .and("principalName").is(principal.getName()));
        MongoAuthorizedClient client = fromAuthorizedClient(authorizedClient, principal);
        mongoTemplate.upsert(query, Update.update("tokenType", client.getTokenType())
                .set("accessToken", client.getAccessToken())
                .set("accessTokenIssuedAt", client.getAccessTokenIssuedAt())
                .set("accessTokenExpiresAt", client.getAccessTokenExpiresAt())
                .set("accessTokenScopes", client.getAccessTokenScopes())
                .set("refreshToken", client.getRefreshToken())
                .set("refreshTokenIssuedAt", client.getRefreshTokenIssuedAt()), MongoAuthorizedClient.class);
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        Query query = new Query(Criteria.where("registrationId").is(clientRegistrationId)
                .and("principalName").is(principalName));
        mongoTemplate.findAllAndRemove(query, MongoAuthorizedClient.class);
    }

    OAuth2AuthorizedClient toAuthorizedClient(MongoAuthorizedClient doc) {
        if (doc == null) {
            return null;
        }
        ClientRegistration registration = clientRepo.findByRegistrationId(doc.getRegistrationId());
        OAuth2AccessToken.TokenType tokenType = null;
        if (OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(doc.getTokenType())) {
            tokenType = OAuth2AccessToken.TokenType.BEARER;
        }
        OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenType, doc.getAccessToken(), doc.getAccessTokenIssuedAt(),
                doc.getAccessTokenExpiresAt(), doc.getAccessTokenScopes());
        OAuth2RefreshToken refreshToken = doc.getRefreshToken() != null ?
                new OAuth2RefreshToken(doc.getRefreshToken(), doc.getRefreshTokenIssuedAt()) : null;
        return new OAuth2AuthorizedClient(registration, doc.getPrincipalName(), accessToken, refreshToken);
    }

    MongoAuthorizedClient fromAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        MongoAuthorizedClient doc = new MongoAuthorizedClient();
        doc.setRegistrationId(authorizedClient.getClientRegistration().getRegistrationId());
        doc.setPrincipalName(principal.getName());
        if (authorizedClient.getAccessToken() != null) {
            doc.setTokenType(authorizedClient.getAccessToken().getTokenType().getValue());
            doc.setAccessToken(authorizedClient.getAccessToken().getTokenValue());
            doc.setAccessTokenIssuedAt(authorizedClient.getAccessToken().getIssuedAt());
            doc.setAccessTokenExpiresAt(authorizedClient.getAccessToken().getExpiresAt());
            doc.setAccessTokenScopes(authorizedClient.getAccessToken().getScopes());
        }
        if (authorizedClient.getRefreshToken() != null) {
            doc.setRefreshToken(authorizedClient.getRefreshToken().getTokenValue());
            doc.setRefreshTokenIssuedAt(authorizedClient.getRefreshToken().getIssuedAt());
        }
        return doc;
    }
}
