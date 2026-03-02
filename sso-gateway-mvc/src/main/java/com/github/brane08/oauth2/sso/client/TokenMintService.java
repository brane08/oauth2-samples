package com.github.brane08.oauth2.sso.client;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.time.Instant;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class TokenMintService {

    private static final Logger log = LoggerFactory.getLogger(TokenMintService.class);

    private final RestTemplate restTemplate;  // For SSO validation
    private final JwtEncoder jwtEncoder;     // For minting JWTs
    private final JwtDecoder jwtDecoder;     // For SSO token validation (if JWT)

    private static final String SSO_ISSUER = "https://auth.example.com:8077";
    private static final String SSO_USERINFO_ENDPOINT = SSO_ISSUER + "/userinfo";

    public TokenMintService(RestTemplateBuilder restTemplateBuilder,
                            JwtEncoder jwtEncoder,
                            JwtDecoder jwtDecoder) {
        this.restTemplate = restTemplateBuilder.build();
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
    }

    /**
     * Validate SSO token and return user details
     */
    public UserDetails validateAndGetUser(String ssoToken) {
        try {
            // Option 1: If SSO token is JWT, decode directly
            Jwt jwt = jwtDecoder.decode(ssoToken);
            if (isValidSsoJwt(jwt)) {
                return jwtToUserDetails(jwt);
            }
        } catch (Exception e) {
            // Not a JWT, try userinfo endpoint
        }

        // Option 2: Introspect via SSO userinfo endpoint
        UserDetails user = callUserInfoEndpoint(ssoToken);
        if (user != null) {
            return user;
        }

        throw new RuntimeException("Invalid SSO token");
    }

    /**
     * Mint a new gateway JWT access token
     */
    public String mintAccessToken(UserDetails userDetails) {
        Instant now = Instant.now();
        Instant expiresAt = now.plusSeconds(3600);  // 1 hour

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("https://auth.example.com:8077")
                .subject(userDetails.getUsername())
                .audience(List.of("backend-services"))  // Your downstream services
                .issuedAt(now)
                .expiresAt(expiresAt)
                .claim("roles", userDetails.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority)
                        .collect(Collectors.toList()))
                .claim("scope", "read write")  // Or from userDetails
                .build();

        return jwtEncoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    /**
     * Call external SSO userinfo endpoint
     */
    private UserDetails callUserInfoEndpoint(String ssoToken) {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.setBearerAuth(ssoToken);
            HttpEntity<String> entity = new HttpEntity<>(headers);

            ResponseEntity<UserInfoResponse> response = restTemplate.exchange(
                    SSO_USERINFO_ENDPOINT,
                    HttpMethod.GET,
                    entity,
                    UserInfoResponse.class);

            if (response.getStatusCode().is2xxSuccessful()) {
                UserInfoResponse userInfo = response.getBody();
                User.UserBuilder builder = User.builder();
                builder.username(userInfo.getSub()).authorities(AuthorityUtils.createAuthorityList("ROLE_USER"));
                return builder.build();
            }
        } catch (Exception e) {
            log.warn("Userinfo endpoint failed", e);
        }
        return null;
    }

    private boolean isValidSsoJwt(Jwt jwt) {
        return SSO_ISSUER.equals(jwt.getIssuer()) &&
                jwt.getExpiresAt().isAfter(Instant.now());
    }

    @SuppressWarnings("unchecked")
    private UserDetails jwtToUserDetails(Jwt jwt) {
        String name = jwt.getClaimAsString("sub");
        String email = jwt.getClaimAsString("email");
        List<String> roles = jwt.getClaimAsStringList("roles");
        Collection<GrantedAuthority> authorities = roles != null ?
                (Collection<GrantedAuthority>) roles.stream().map(role -> (GrantedAuthority) () -> "ROLE_" + role)
                : AuthorityUtils.createAuthorityList("ROLE_USER");

        return User.builder().username(name).authorities(authorities).build();
    }
}
