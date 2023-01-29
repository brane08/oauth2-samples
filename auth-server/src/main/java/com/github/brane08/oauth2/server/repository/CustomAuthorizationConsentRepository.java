package com.github.brane08.oauth2.server.repository;

import com.github.brane08.oauth2.server.domain.CustomAuthorizationConsent;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CustomAuthorizationConsentRepository extends ListCrudRepository<CustomAuthorizationConsent, String> {
    Optional<CustomAuthorizationConsent> findByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);

    void deleteByRegisteredClientIdAndPrincipalName(String registeredClientId, String principalName);
}
