package com.github.brane08.oauth2.server.web.utils;

import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class RequestUtils {

	private RequestUtils() {

	}

	public static RequestMatcher getOauth2RequestMatcher() {
		return new OrRequestMatcher(
				PathPatternRequestMatcher.pathPattern("/oauth2/authorize"),
				PathPatternRequestMatcher.pathPattern("/.well-known/**")
		);
	}
}
