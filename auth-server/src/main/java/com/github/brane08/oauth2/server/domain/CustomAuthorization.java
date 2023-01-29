package com.github.brane08.oauth2.server.domain;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.time.Instant;

@Table(name = "oauth2_authorization")
public class CustomAuthorization {
    @Id
    @Column("id")
    private String id;
    @Column("registered_client_id")
    private String registeredClientId;
    @Column("principal_name")
    private String principalName;
    @Column("authorization_grant_type")
    private String authorizationGrantType;
    @Column("authorized_scopes")
    private String authorizedScopes;
    @Column("attributes")
    private String attributes;
    @Column("state")
    private String state;
    @Column("authorization_code_value")
    private String authorizationCodeValue;
    @Column("authorization_code_issued_at")
    private Instant authorizationCodeIssuedAt;
    @Column("authorization_code_expires_at")
    private Instant authorizationCodeExpiresAt;
    @Column("authorization_code_metadata")
    private String authorizationCodeMetadata;
    @Column("access_token_value")
    private String accessTokenValue;
    @Column("access_token_issued_at")
    private Instant accessTokenIssuedAt;
    @Column("access_token_expires_at")
    private Instant accessTokenExpiresAt;
    @Column("access_token_metadata")
    private String accessTokenMetadata;
    @Column("access_token_type")
    private String accessTokenType;
    @Column("access_token_scopes")
    private String accessTokenScopes;

    @Column("refresh_token_value")
    private String refreshTokenValue;
    @Column("refresh_token_issued_at")
    private Instant refreshTokenIssuedAt;
    @Column("refresh_token_expires_at")
    private Instant refreshTokenExpiresAt;
    @Column("refresh_token_metadata")
    private String refreshTokenMetadata;

    @Column("oidc_id_token_value")
    private String oidcIdTokenValue;
    @Column("oidc_id_token_issued_at")
    private Instant oidcIdTokenIssuedAt;
    @Column("oidc_id_token_expires_at")
    private Instant oidcIdTokenExpiresAt;
    @Column("oidc_id_token_metadata")
    private String oidcIdTokenMetadata;
    @Column("oidc_id_token_claims")
    private String oidcIdTokenClaims;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getRegisteredClientId() {
        return registeredClientId;
    }

    public void setRegisteredClientId(String registeredClientId) {
        this.registeredClientId = registeredClientId;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    public String getAuthorizationGrantType() {
        return authorizationGrantType;
    }

    public void setAuthorizationGrantType(String authorizationGrantType) {
        this.authorizationGrantType = authorizationGrantType;
    }

    public String getAuthorizedScopes() {
        return this.authorizedScopes;
    }

    public void setAuthorizedScopes(String authorizedScopes) {
        this.authorizedScopes = authorizedScopes;
    }

    public String getAttributes() {
        return attributes;
    }

    public void setAttributes(String attributes) {
        this.attributes = attributes;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public String getAuthorizationCodeValue() {
        return authorizationCodeValue;
    }

    public void setAuthorizationCodeValue(String authorizationCode) {
        this.authorizationCodeValue = authorizationCode;
    }

    public Instant getAuthorizationCodeIssuedAt() {
        return authorizationCodeIssuedAt;
    }

    public void setAuthorizationCodeIssuedAt(Instant authorizationCodeIssuedAt) {
        this.authorizationCodeIssuedAt = authorizationCodeIssuedAt;
    }

    public Instant getAuthorizationCodeExpiresAt() {
        return authorizationCodeExpiresAt;
    }

    public void setAuthorizationCodeExpiresAt(Instant authorizationCodeExpiresAt) {
        this.authorizationCodeExpiresAt = authorizationCodeExpiresAt;
    }

    public String getAuthorizationCodeMetadata() {
        return authorizationCodeMetadata;
    }

    public void setAuthorizationCodeMetadata(String authorizationCodeMetadata) {
        this.authorizationCodeMetadata = authorizationCodeMetadata;
    }

    public String getAccessTokenValue() {
        return accessTokenValue;
    }

    public void setAccessTokenValue(String accessToken) {
        this.accessTokenValue = accessToken;
    }

    public Instant getAccessTokenIssuedAt() {
        return accessTokenIssuedAt;
    }

    public void setAccessTokenIssuedAt(Instant accessTokenIssuedAt) {
        this.accessTokenIssuedAt = accessTokenIssuedAt;
    }

    public Instant getAccessTokenExpiresAt() {
        return accessTokenExpiresAt;
    }

    public void setAccessTokenExpiresAt(Instant accessTokenExpiresAt) {
        this.accessTokenExpiresAt = accessTokenExpiresAt;
    }

    public String getAccessTokenMetadata() {
        return accessTokenMetadata;
    }

    public void setAccessTokenMetadata(String accessTokenMetadata) {
        this.accessTokenMetadata = accessTokenMetadata;
    }

    public String getAccessTokenType() {
        return accessTokenType;
    }

    public void setAccessTokenType(String accessTokenType) {
        this.accessTokenType = accessTokenType;
    }

    public String getAccessTokenScopes() {
        return accessTokenScopes;
    }

    public void setAccessTokenScopes(String accessTokenScopes) {
        this.accessTokenScopes = accessTokenScopes;
    }

    public String getRefreshTokenValue() {
        return refreshTokenValue;
    }

    public void setRefreshTokenValue(String refreshToken) {
        this.refreshTokenValue = refreshToken;
    }

    public Instant getRefreshTokenIssuedAt() {
        return refreshTokenIssuedAt;
    }

    public void setRefreshTokenIssuedAt(Instant refreshTokenIssuedAt) {
        this.refreshTokenIssuedAt = refreshTokenIssuedAt;
    }

    public Instant getRefreshTokenExpiresAt() {
        return refreshTokenExpiresAt;
    }

    public void setRefreshTokenExpiresAt(Instant refreshTokenExpiresAt) {
        this.refreshTokenExpiresAt = refreshTokenExpiresAt;
    }

    public String getRefreshTokenMetadata() {
        return refreshTokenMetadata;
    }

    public void setRefreshTokenMetadata(String refreshTokenMetadata) {
        this.refreshTokenMetadata = refreshTokenMetadata;
    }

    public String getOidcIdTokenValue() {
        return oidcIdTokenValue;
    }

    public void setOidcIdTokenValue(String idToken) {
        this.oidcIdTokenValue = idToken;
    }

    public Instant getOidcIdTokenIssuedAt() {
        return oidcIdTokenIssuedAt;
    }

    public void setOidcIdTokenIssuedAt(Instant idTokenIssuedAt) {
        this.oidcIdTokenIssuedAt = idTokenIssuedAt;
    }

    public Instant getOidcIdTokenExpiresAt() {
        return oidcIdTokenExpiresAt;
    }

    public void setOidcIdTokenExpiresAt(Instant idTokenExpiresAt) {
        this.oidcIdTokenExpiresAt = idTokenExpiresAt;
    }

    public String getOidcIdTokenMetadata() {
        return oidcIdTokenMetadata;
    }

    public void setOidcIdTokenMetadata(String idTokenMetadata) {
        this.oidcIdTokenMetadata = idTokenMetadata;
    }

    public String getOidcIdTokenClaims() {
        return oidcIdTokenClaims;
    }

    public void setOidcIdTokenClaims(String idTokenClaims) {
        this.oidcIdTokenClaims = idTokenClaims;
    }

}
