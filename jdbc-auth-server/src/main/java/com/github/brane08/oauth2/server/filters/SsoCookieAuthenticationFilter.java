package com.github.brane08.oauth2.server.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import java.io.IOException;
import java.util.Optional;

public class SsoCookieAuthenticationFilter extends OncePerRequestFilter {

    private static final Logger LOG =
            LoggerFactory.getLogger(SsoCookieAuthenticationFilter.class);

    private final AuthenticationManager authenticationManager;
    private final SecurityContextRepository securityContextRepository;
    private final AuthenticationSuccessHandler successHandler;
    private final RequestCache requestCache;
    private final RequestMatcher staticResourcesMatcher;
    private final RequestMatcher publicPathMatcher;
    private final RequestMatcher oauth2ProtectedMatcher;
    private final String gatewayBaseUrl;
    private final boolean useRedirectInFilter;

    public SsoCookieAuthenticationFilter(AuthenticationManager authenticationManager,
                                         SecurityContextRepository securityContextRepository,
                                         AuthenticationSuccessHandler successHandler,
                                         RequestCache requestCache,
                                         RequestMatcher staticResourcesMatcher,
                                         RequestMatcher publicPathMatcher,
                                         RequestMatcher oauth2ProtectedMatcher,
                                         String gatewayBaseUrl,
                                         boolean useRedirectInFilter) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
        this.successHandler = successHandler;
        this.requestCache = requestCache;
        this.staticResourcesMatcher = staticResourcesMatcher;
        this.publicPathMatcher = publicPathMatcher;
        this.oauth2ProtectedMatcher = oauth2ProtectedMatcher;
        this.gatewayBaseUrl = gatewayBaseUrl;
        this.useRedirectInFilter = useRedirectInFilter;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        if (staticResourcesMatcher.matches(request)) return true;
        if (publicPathMatcher.matches(request)) return true;
        return !oauth2ProtectedMatcher.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        LOG.debug("============= Start processing Sso Cookie Authentication Request ============");
        var firstAuth = SecurityContextHolder.getContext().getAuthentication();
        var isRealUser = firstAuth != null && firstAuth.isAuthenticated() && !"anonymousUser".equals(firstAuth.getName());
        // If already authenticated, do nothing
        if (isRealUser) {
            LOG.debug("Found valid authentication for user: {}, uri: {}", firstAuth.getName(), request.getRequestURI());
            filterChain.doFilter(request, response);
            return;
        }

        Cookie ssoCookie = getGatewayCookie(request);
        if (ssoCookie == null || ssoCookie.getValue() == null) {
            if (useRedirectInFilter) {
                LOG.debug("No cookie found in uri: {}, should redirect to gateway base", request.getRequestURI());
                if (isHtmlRequest(request)) {
                    String[] values = request.getParameterValues("sso_continue");
                    int retryCount = 1;
                    if (values != null && values.length > 0 && values[0] != null) {
                        try {
                            retryCount = Integer.parseInt(values[0]);
                        } catch (NumberFormatException e) {
                            LOG.warn("Could not parse 'sso_continue' integer: {}", values[0]);
                        }
                    }
                    LOG.debug("Authentication entrypoint handling html request, redirect to gateway base url");
                    String redirectUrl = gatewayBaseUrl + "?sso_continue=" + retryCount;
                    response.setStatus(HttpServletResponse.SC_FOUND);
                    response.setHeader("Location", redirectUrl);
                    return;
                } else {
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType("application/json");
                    response.getWriter().write("{\"error\":\"unauthorized\",\"message\":\"Authentication required\"}");
                    return;
                }
            } else {
                LOG.debug("No cookie found in uri: {}, continue chain", request.getRequestURI());
                filterChain.doFilter(request, response);
                return;
            }
        } else {
            try {
                LOG.debug("SSO cookie found, attempting pre-authentication");
                UsernamePasswordAuthenticationToken authRequest = new UsernamePasswordAuthenticationToken(ssoCookie.getValue(), ssoCookie.getValue());
                Authentication authentication = authenticationManager.authenticate(authRequest);
                request.getSession(true);
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(authentication);
                SecurityContextHolder.setContext(context);
                securityContextRepository.saveContext(context, request, response);
                requestCache.saveRequest(request, response);
                LOG.debug("SSO authentication successful for user {}", authentication.getName());
                successHandler.onAuthenticationSuccess(request, response, authentication);
                return;
            } catch (AuthenticationException e) {
                LOG.debug("SSO authentication unsuccessful for user {}", ssoCookie.getValue(), e);
                SecurityContextHolder.clearContext();
            }
        }
        filterChain.doFilter(request, response);
    }

    private Cookie getGatewayCookie(HttpServletRequest request) {
        var cookie = WebUtils.getCookie(request, "GATEWAY_SSO");
        if (cookie == null) {
            logger.warn("Gateway sso cookie missing falling back to original sso cookie");
            cookie = WebUtils.getCookie(request, "SSO_TOKEN");
        }
        return cookie;
    }

    private boolean isHtmlRequest(HttpServletRequest request) {
        String accept = request.getHeader("Accept");
        if (accept != null && accept.contains("text/html")) return true;
        String path = request.getRequestURI();
        return !path.contains(".") || path.endsWith(".html");
    }
}
