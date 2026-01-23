package com.github.brane08.oauth2.server.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.ArrayList;
import java.util.List;

@Configuration
public class SecurityConfig {

	private final List<String> staticPaths = List.of("/**/*.css", "/**/*.js", "/**/*.map", "/**/*.html", "/**/*.wasm",
			"/**/*.png", "/**/*.jpg", "/**/*.jpeg", "/**/*.svg", "/**/*.ico", "/**/*.gif", "/**/*.woff", "/**/*.woff2",
			"/**/*.ttf", "/**/*.eot", "/assets/**");

	@Bean
	public RequestMatcher staticResourcesMatcher() {
		return new OrRequestMatcher(getRequestMatchers(staticPaths));
	}

	@Bean
	public RequestMatcher publicPathMatcher() {
		return new OrRequestMatcher(getRequestMatchers(List.of("/.well-known/**", "/oauth2/jwks", "/actuator/**",
				"/info", "/processing", "/error")));
	}

	@Bean
	public RequestMatcher oauth2ProtectedMatcher() {
		return new OrRequestMatcher(
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/oauth2/authorize"),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/oauth2/authorize/**"),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/oauth2/token"),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/oauth2/introspect"),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.POST, "/oauth2/revoke"),
				PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, "/userinfo"));
	}

	List<RequestMatcher> getRequestMatchers(List<String> paths) {
		List<RequestMatcher> requestMatchers = new ArrayList<>();
		for (String path : paths) {
			requestMatchers.add(PathPatternRequestMatcher.withDefaults().matcher(path));
		}
		return  requestMatchers;
	}
}
