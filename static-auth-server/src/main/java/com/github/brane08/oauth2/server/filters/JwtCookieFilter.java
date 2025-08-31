package com.github.brane08.oauth2.server.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
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

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
									FilterChain filterChain) throws ServletException, IOException {
		logger.info("JwtCookieFilter hit for: {}", request.getRequestURI());
		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			String username = extractTokenFromCookie(request);
			if (username != null) {
				List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("ROLE_USER");

				UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
				auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
				SecurityContextHolder.getContext().setAuthentication(auth);
				logger.info("Authenticated user from cookie: {}", username);
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
