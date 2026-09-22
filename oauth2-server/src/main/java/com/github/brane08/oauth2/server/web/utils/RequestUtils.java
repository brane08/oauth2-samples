package com.github.brane08.oauth2.server.web.utils;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;

public class RequestUtils {

    private static final List<String> STATIC_EXTENSIONS = List.of("/**/*.js", "/**/*.css", "/**/*.map","/**/*.png","/**/*.ico");

    /** Max SSO gateway round-trips before we give up instead of redirecting forever. */
    public static final int MAX_SSO_REDIRECT_ATTEMPTS = 3;

    private RequestUtils() {

    }

    public static RequestMatcher getOauth2RequestMatcher() {
        return new OrRequestMatcher(
                PathPatternRequestMatcher.withDefaults().matcher("/oauth2/authorize"),
                PathPatternRequestMatcher.withDefaults().matcher("/.well-known/**")
        );
    }

    public static int parseSsoRetryCount(HttpServletRequest request) {
        String[] values = request.getParameterValues("sso_continue");
        if (values != null && values.length > 0 && values[0] != null) {
            try {
                return Integer.parseInt(values[0]);
            } catch (NumberFormatException ignored) {
                // treat unparsable value as the start of a new attempt count
            }
        }
        return 0;
    }
}
