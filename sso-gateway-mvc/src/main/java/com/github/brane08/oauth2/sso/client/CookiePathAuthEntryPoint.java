package com.github.brane08.oauth2.sso.client;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class CookiePathAuthEntryPoint implements AuthenticationEntryPoint {

    private static final Logger log = LoggerFactory.getLogger(CookiePathAuthEntryPoint.class);

    private final String cookieName = "SSO_TOKEN";
    private final String rootPath;

    public CookiePathAuthEntryPoint(String rootPath) {
        this.rootPath = rootPath;
    }

    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res,
                         AuthenticationException ex) throws IOException {
        String targetUrl = req.getRequestURI();

        // Check if cookie missing due to path
        Cookie[] cookies = req.getCookies();
        boolean hasCookie = cookies != null && Arrays.stream(cookies)
                .anyMatch(c -> cookieName.equals(c.getName()));
        log.debug("AuthEntryPoint: targetUrl={}, hasCookie={}", targetUrl, hasCookie);
        if (!hasCookie && !targetUrl.equals(rootPath)) {
            // Redirect to root to set cookie
            String redirectPart = "";
            if (!"/".equalsIgnoreCase(targetUrl)) {
                redirectPart = "?redirect=" + URLEncoder.encode(targetUrl, StandardCharsets.UTF_8);
            }
            String redirectToRoot = rootPath + redirectPart;
            log.debug("AuthEntryPoint: redirectToRoot={}", redirectToRoot);
            res.sendRedirect(redirectToRoot);
            return;
        }

        // Normal 401 JSON or login
        res.setStatus(401);
        res.setContentType("application/json");
        res.getWriter().write("{\"error\":\"auth_required\",\"path\":\"/\"}");
    }
}
