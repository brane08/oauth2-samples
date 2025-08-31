package com.github.brane08.oauth2.server.repository;

import com.github.brane08.oauth2.server.domain.CustomAuthorization;
import org.springframework.data.jdbc.repository.query.Query;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CustomAuthorizationRepository extends ListCrudRepository<CustomAuthorization, String> {

    Optional<CustomAuthorization> findByState(String state);

    Optional<CustomAuthorization> findByAuthorizationCodeValue(String authorizationCode);

    Optional<CustomAuthorization> findByAccessTokenValue(String accessToken);

    Optional<CustomAuthorization> findByRefreshTokenValue(String refreshToken);

    @Query("select a from oauth2_authorization a where a.state = :token" +
            " or a.authorization_code_value = :token" +
            " or a.access_token_value = :token" +
            " or a.refresh_token_value = :token"
    )
    Optional<CustomAuthorization> findByStateOrAuthorizationCodeValueOrAccessTokenValueOrRefreshTokenValue(@Param("token") String token);
}
