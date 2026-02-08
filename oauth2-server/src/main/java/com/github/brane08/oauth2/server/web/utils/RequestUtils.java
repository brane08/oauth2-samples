package com.github.brane08.oauth2.server.web.utils;

import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.List;

public class RequestUtils {

    private static final List<String> STATIC_EXTENSIONS = List.of("/**/*.js", "/**/*.css", "/**/*.map","/**/*.png","/**/*.ico");

    private RequestUtils() {

    }

    public static RequestMatcher getOauth2RequestMatcher() {
        return new OrRequestMatcher(
                PathPatternRequestMatcher.withDefaults().matcher("/oauth2/authorize"),
                PathPatternRequestMatcher.withDefaults().matcher("/.well-known/**")
        );
    }
}
