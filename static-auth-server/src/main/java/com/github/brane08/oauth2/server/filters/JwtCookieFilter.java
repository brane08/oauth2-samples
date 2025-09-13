package com.github.brane08.oauth2.server.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class JwtCookieFilter extends OncePerRequestFilter {
	private static final String SECRET_KEY = "XLxwEzxLmowhWCuOSzSQrm6GoI0PJFByD08n4XYs+f8XtZMh6ioy7fzzgmCRmjQK";
	private static final Logger logger = LoggerFactory.getLogger(JwtCookieFilter.class);
	private final String cookieName = "SSO_TOKEN";
	private JwtDecoder jwtDecoder;
	private final UserDetailsService delegate;
	private final RequestMatcher appliesTo;
	private final SecurityContextRepository contextRepo = new HttpSessionSecurityContextRepository();
	private final AuthenticationSuccessHandler successHandler;

	public JwtCookieFilter(UserDetailsService delegate, AuthenticationSuccessHandler successHandler) {
		this.delegate = delegate;
		this.successHandler = successHandler;
		this.appliesTo = new OrRequestMatcher(
				PathPatternRequestMatcher.withDefaults().matcher("/login"),
				PathPatternRequestMatcher.withDefaults().matcher("/oauth/authorize")
		);
	}

	@Override
	protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
		if (!appliesTo.matches(request)) return true;
		if (SecurityContextHolder.getContext().getAuthentication() != null) return true;
		return extractTokenFromCookie(request) == null;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
									FilterChain filterChain) throws ServletException, IOException {
		logger.info("JwtCookieFilter hit for: {}", request.getRequestURI());
		String username = extractTokenFromCookie(request);
		if (username != null) {
			try {
				UserDetails user = delegate.loadUserByUsername(username);
				var auth = UsernamePasswordAuthenticationToken.authenticated(
						user, user.getPassword(), user.getAuthorities());
				auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				var context = SecurityContextHolder.createEmptyContext();
				context.setAuthentication(auth);
				SecurityContextHolder.setContext(context);

				// persist to HTTP session so subsequent requests remain authenticated
				contextRepo.saveContext(context, request, response);

				logger.debug("Cookie pre-auth succeeded for '{}'", username);
				successHandler.onAuthenticationSuccess(request, response, auth);
			} catch (Exception ex) {
				logger.debug("Cookie pre-auth failed for '{}'", username, ex);
				// fall through to normal flow (login page, etc.)
			}
		}
		filterChain.doFilter(request, response);
	}

	private String extractTokenFromCookie(HttpServletRequest request) {
		if (request.getCookies() == null) return null;

		for (Cookie cookie : request.getCookies()) {
			if (cookieName.equals(cookie.getName())) {
				logger.info("Found cookie '{}'", cookie.getValue());
				return cookie.getValue();
			}
		}
		return null;
	}

	private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
		Object rolesClaim = jwt.getClaims().get("roles");
		if (rolesClaim instanceof List<?>) {
			return ((List<?>) rolesClaim).stream()
					.map(Object::toString)
					.map(r -> new SimpleGrantedAuthority("ROLE_" + r))
					.collect(Collectors.toList());
		} else if (rolesClaim instanceof String roleString) {
			return List.of(new SimpleGrantedAuthority("ROLE_" + roleString));
		}
		return Collections.emptyList();
	}

	JwtDecoder jwtDecoder() {
		if (this.jwtDecoder == null) {
			this.jwtDecoder = NimbusJwtDecoder.withSecretKey(
					new SecretKeySpec(SECRET_KEY.getBytes(), "HmacSHA256")
			).build();
		}
		return this.jwtDecoder;
	}
}
