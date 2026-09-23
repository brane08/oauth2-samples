package com.github.brane08.oauth2.sso.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Trusts the {@value #PING_USER_HEADER} header injected by the fronting SSO (httpd in test
 * environments, a Ping-style IdP in production) as an already-authenticated principal, skipping
 * this gateway's own OIDC login. Only active under the {@code ping-preauth} profile.
 */
public class PingPreAuthenticationFilter extends OncePerRequestFilter {

    public static final String PING_USER_HEADER = "Sm_user";

    private final SecurityContextRepository securityContextRepository;

    public PingPreAuthenticationFilter(SecurityContextRepository securityContextRepository) {
        this.securityContextRepository = securityContextRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        Authentication existing = SecurityContextHolder.getContext().getAuthentication();
        if (existing != null && existing.isAuthenticated() && !(existing instanceof AnonymousAuthenticationToken)) {
            filterChain.doFilter(request, response);
            return;
        }

        String username = request.getHeader(PING_USER_HEADER);
        if (StringUtils.hasText(username)) {
            PreAuthenticatedAuthenticationToken authentication = new PreAuthenticatedAuthenticationToken(
                    username, "N/A", AuthorityUtils.createAuthorityList("ROLE_USER"));
            authentication.setAuthenticated(true);

            SecurityContext context = SecurityContextHolder.createEmptyContext();
            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);
            this.securityContextRepository.saveContext(context, request, response);
        }

        filterChain.doFilter(request, response);
    }
}
