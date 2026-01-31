package com.github.brane08.oauth2.server.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
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
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.WebUtils;

import java.io.IOException;

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

    public SsoCookieAuthenticationFilter(AuthenticationManager authenticationManager,
                                         SecurityContextRepository securityContextRepository,
                                         AuthenticationSuccessHandler successHandler,
                                         RequestCache requestCache,
                                         RequestMatcher staticResourcesMatcher,
                                         RequestMatcher publicPathMatcher,
                                         RequestMatcher oauth2ProtectedMatcher,
                                         String gatewayBaseUrl) {
        this.authenticationManager = authenticationManager;
        this.securityContextRepository = securityContextRepository;
        this.successHandler = successHandler;
        this.requestCache = requestCache;
        this.staticResourcesMatcher = staticResourcesMatcher;
        this.publicPathMatcher = publicPathMatcher;
        this.oauth2ProtectedMatcher = oauth2ProtectedMatcher;
        this.gatewayBaseUrl = gatewayBaseUrl;
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
            filterChain.doFilter(request, response);
            return;
        }

        Cookie ssoCookie = WebUtils.getCookie(request, "SSO_TOKEN");
        if (ssoCookie == null || ssoCookie.getValue() == null) {
            if (isHtmlRequest(request)) {
                String redirectUrl = gatewayBaseUrl + request.getRequestURI();
                if (request.getQueryString() != null) redirectUrl += "?" + request.getQueryString();
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

    private boolean isHtmlRequest(HttpServletRequest request) {
        String accept = request.getHeader("Accept");
        if (accept != null && accept.contains("text/html")) return true;
        String path = request.getRequestURI();
        return !path.contains(".") || path.endsWith(".html");
    }
}
