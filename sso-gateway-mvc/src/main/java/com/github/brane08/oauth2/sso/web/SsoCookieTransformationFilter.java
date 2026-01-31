package com.github.brane08.oauth2.sso.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class SsoCookieTransformationFilter extends OncePerRequestFilter {

    private static final Authentication ANONYMOUS_FALLBACK =
            new AnonymousAuthenticationToken("sso-filter", "anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
    private static final String ORIGINAL_SSO_COOKIE = "SSO_TOKEN";
    private static final String GATEWAY_SSO_COOKIE = "GATEWAY_SSO";
    private static final String SSO_TOKEN_HEADER = "X-SSO-Token";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        if (shouldSkip(request)) {
            filterChain.doFilter(request, response);
            return;
        }
        request.setAttribute("sso_cookie_processed", true);

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
            filterChain.doFilter(request, response);
            return;
        }

        processSsoCookie(request, response, filterChain);
    }

    private void processSsoCookie(HttpServletRequest request, HttpServletResponse response,
                                  FilterChain filterChain) throws IOException, ServletException {

        if (hasGatewayCookie(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String headerToken = request.getHeader(SSO_TOKEN_HEADER);
        String ssoToken = headerToken;
        if (ssoToken == null) {
            Cookie[] cookies = request.getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (ORIGINAL_SSO_COOKIE.equals(cookie.getName())) {
                        ssoToken = cookie.getValue();
                        break;
                    }
                }
            }
        }

        if (ssoToken != null) {
            Cookie gatewayCookie = new Cookie(GATEWAY_SSO_COOKIE, ssoToken);
            gatewayCookie.setPath("/");
            gatewayCookie.setHttpOnly(true);
            gatewayCookie.setSecure(true);
            gatewayCookie.setDomain("example.com");
            gatewayCookie.setAttribute("SameSite", "None");
            response.addCookie(gatewayCookie);
        }

        filterChain.doFilter(request, response);
    }

    private boolean hasGatewayCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (GATEWAY_SSO_COOKIE.equals(cookie.getName())) {
                    return true;
                }
            }
        }
        return false;
    }

    private boolean shouldSkip(HttpServletRequest request) {
        String path = request.getRequestURI();
        return request.getAttribute("sso_cookie_processed") != null ||
                responseIsCommitted(request) ||
                path.startsWith("/oauth2/") ||
                path.startsWith("/login/");
    }

    // Servlet equivalent check (approximation)
    private boolean responseIsCommitted(HttpServletRequest request) {
        // In servlet filters, we can't directly check response.isCommitted() before doFilter
        // This is handled by OncePerRequestFilter automatically
        return false;
    }
}
