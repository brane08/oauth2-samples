package com.github.brane08.oauth2.sso.web;

import com.github.brane08.oauth2.sso.client.TokenMintService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

public class SsoJwtTransformationFilter extends OncePerRequestFilter {

    private static final String ORIGINAL_SSO_COOKIE = "SSO_TOKEN";
    private static final String GATEWAY_SSO_COOKIE = "GATEWAY_SSO";
    private static final String SSO_TOKEN_HEADER = "x-sso-user";
    private static final String CLIENT_REG_ID = "client-oidc";

    private static final Logger LOG =
            LoggerFactory.getLogger(SsoJwtTransformationFilter.class);

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final RequestCache requestCache;
    private final RequestMatcher staticResourcesMatcher;
    private final ClientRegistrationRepository clientRepo;
    private final OAuth2AuthorizedClientService authorizedClientService;
    private final TokenMintService mintService;

    public SsoJwtTransformationFilter(AuthenticationManager authenticationManager,
                                      SecurityContextRepository securityContextRepository,
                                      RequestCache requestCache,
                                      RequestMatcher staticResourcesMatcher,
                                      ClientRegistrationRepository clientRepo,
                                      OAuth2AuthorizedClientService authorizedClientService,
                                      TokenMintService mintService) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
        this.requestCache = requestCache;
        this.staticResourcesMatcher = staticResourcesMatcher;
        this.clientRepo = clientRepo;
        this.authorizedClientService = authorizedClientService;
        this.mintService = mintService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return staticResourcesMatcher.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        LOG.debug("============= Start processing Sso Jwt Authentication Request ============");
        var firstAuth = SecurityContextHolder.getContext().getAuthentication();
        var isRealUser = firstAuth != null && firstAuth.isAuthenticated() && !"anonymousUser".equals(firstAuth.getName());
        // If already authenticated, do nothing
        if (isRealUser) {
            LOG.debug("Found valid authentication for user: {}, uri: {}", firstAuth.getName(), request.getRequestURI());
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(CLIENT_REG_ID, firstAuth.getName());
            if (client == null || Instant.now().isAfter(client.getAccessToken().getExpiresAt())) {
                LOG.debug("No valid OAuth2 client found for user {}, minting new JWT token", firstAuth.getName());
                mintJwtToken(firstAuth);
            } else {
                LOG.debug("Valid OAuth2 client found for user {}, token expires at {}", firstAuth.getName(), client.getAccessToken().getExpiresAt());
            }
            filterChain.doFilter(request, response);
            return;
        }

        String ssoValue = getGatewayCookie(request);
        if (ssoValue == null) {
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"unauthorized\",\"message\":\"Authentication required\"}");
        } else {
            try {
                LOG.debug("SSO cookie found, attempting pre-authentication");
                UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(ssoValue, ssoValue);
                Authentication authentication = authenticationManager.authenticate(authRequest);
                request.getSession(true);
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);
                securityContextRepository.saveContext(context, request, response);
                requestCache.saveRequest(request, response);
                mintJwtToken(authentication);
                LOG.debug("SSO authentication successful for user {}", authentication.getName());
                return;
            } catch (AuthenticationException e) {
                LOG.debug("SSO authentication unsuccessful for user {}", ssoValue, e);
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request, response);
    }

    private void mintJwtToken(Authentication authentication) {
        LOG.debug("Minting JWT token for user {}", authentication.getName());
        if (authentication.getPrincipal() instanceof UserDetails details) {
            // Create and save OAuth2AuthorizedClient with user principal
            String accessToken = mintService.mintAccessToken(details);
            OAuth2AccessToken auth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(),
                    Instant.now().plus(4, ChronoUnit.HOURS), Set.of("openid", "profile", "email"));
            ClientRegistration registration = clientRepo.findByRegistrationId(CLIENT_REG_ID);
            OAuth2AuthorizedClient authorizedClient = new OAuth2AuthorizedClient(
                    registration, authentication.getName(), auth2AccessToken, null);
            LOG.debug("Saving JWT token for user {}", authentication.getName());
            authorizedClientService.saveAuthorizedClient(authorizedClient, authentication);
        }
        if (LOG.isDebugEnabled()) {
            OAuth2AuthorizedClient client = authorizedClientService.loadAuthorizedClient(CLIENT_REG_ID, authentication.getName());
            LOG.info("Relayed token: " + client.getAccessToken().getTokenValue().substring(0, 20) + "...");
        }
    }

    private String getGatewayCookie(HttpServletRequest request) {
        var cookie = WebUtils.getCookie(request, GATEWAY_SSO_COOKIE);
        if (cookie == null) {
            logger.warn("Gateway sso cookie missing falling back to original sso cookie");
            cookie = WebUtils.getCookie(request, ORIGINAL_SSO_COOKIE);
            if (cookie == null) {
                logger.warn("Original sso cookie missing, trying header");

                return request.getHeader(SSO_TOKEN_HEADER);
            }
        }
        return cookie != null ? cookie.getValue() : null;
    }

    private boolean isHtmlRequest(HttpServletRequest request) {
        String accept = request.getHeader("Accept");
        if (accept != null && accept.contains("text/html")) return true;
        String path = request.getRequestURI();
        return !path.contains(".") || path.endsWith(".html");
    }
}
