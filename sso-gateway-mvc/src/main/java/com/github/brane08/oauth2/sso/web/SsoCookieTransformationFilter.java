package com.github.brane08.oauth2.sso.web;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import java.io.IOException;

public class SsoCookieTransformationFilter extends OncePerRequestFilter {

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

//        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
//        if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
//            filterChain.doFilter(request, response);
//            return;
//        }

        processSsoCookie(request, response, filterChain);
    }

    private void processSsoCookie(HttpServletRequest request, HttpServletResponse response,
                                  FilterChain filterChain) throws IOException, ServletException {

        if (hasGatewayCookie(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String ssoToken = getHeaderOrCookie(request);
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

    private String getHeaderOrCookie(HttpServletRequest request) {
        String headerToken = request.getHeader(SSO_TOKEN_HEADER);
        if (headerToken == null) {
            Cookie existingCookie = WebUtils.getCookie(request, ORIGINAL_SSO_COOKIE);
            if (existingCookie != null) {
                headerToken = existingCookie.getValue();
            }
        }
        return headerToken;
    }

    private boolean hasGatewayCookie(HttpServletRequest request) {
        Cookie ssoCookie = WebUtils.getCookie(request, GATEWAY_SSO_COOKIE);
        return (ssoCookie != null && ssoCookie.getValue() != null);
    }

    private boolean shouldSkip(HttpServletRequest request) {
        String path = request.getRequestURI();
        return request.getAttribute("sso_cookie_processed") != null ||
                "OPTIONS".equals(request.getMethod());
    }
}
