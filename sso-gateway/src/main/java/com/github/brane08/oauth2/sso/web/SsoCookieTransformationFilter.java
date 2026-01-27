package com.github.brane08.oauth2.sso.web;

import org.springframework.http.HttpCookie;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.time.Duration;

public class SsoCookieTransformationFilter implements WebFilter {

	private static final Authentication ANONYMOUS_FALLBACK =
			new AnonymousAuthenticationToken("sso-filter", "anonymous", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
	private static final String ORIGINAL_SSO_COOKIE = "SSO_TOKEN";
	private static final String GATEWAY_SSO_COOKIE = "GATEWAY_SSO";
	private static final String SSO_USERNAME_HEADER = "X-SSO-Username";
	private static final String SSO_TOKEN_HEADER = "X-SSO-Token";

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		if (shouldSkip(exchange)) {
			return chain.filter(exchange);
		}
		exchange.getAttributes().put("sso_cookie_processed", true);

		return ReactiveSecurityContextHolder.getContext()
				.mapNotNull(SecurityContext::getAuthentication)
				.defaultIfEmpty(ANONYMOUS_FALLBACK)
				.flatMap(auth -> {
					if (auth != null && auth.isAuthenticated() && !(auth instanceof AnonymousAuthenticationToken)) {
						return chain.filter(exchange);
					}
					return processSsoCookie(exchange, chain);
				});
	}

	private Mono<Void> processSsoCookie(ServerWebExchange exchange, WebFilterChain chain) {
		if (hasGatewayCookie(exchange)) {
			return chain.filter(exchange);
		}

		String headerToken = exchange.getRequest().getHeaders().getFirst(SSO_TOKEN_HEADER);
		HttpCookie originalCookie = exchange.getRequest().getCookies().getFirst(ORIGINAL_SSO_COOKIE);
		String ssoToken = headerToken != null ? headerToken : (originalCookie != null ? originalCookie.getValue() : null);

		if (ssoToken != null) {
			ResponseCookie gatewayCookie = ResponseCookie.from(GATEWAY_SSO_COOKIE, ssoToken)
					.path("/").httpOnly(true).secure(true).sameSite("Lax").maxAge(Duration.ofHours(8)).build();
			exchange.getResponse().addCookie(gatewayCookie);
		}

		return chain.filter(exchange);  // No request mutation needed
	}

	private boolean hasGatewayCookie(ServerWebExchange exchange) {
		return exchange.getRequest().getCookies().containsKey(GATEWAY_SSO_COOKIE);
	}

	private boolean shouldSkip(ServerWebExchange exchange) {
		String path = exchange.getRequest().getURI().getPath();
		return exchange.getAttribute("sso_cookie_processed") != null ||
				exchange.getResponse().isCommitted() ||
				path.startsWith("/oauth2/") ||    // Skip auth flows
				path.startsWith("/login/");       // Skip login/callback
	}
}
