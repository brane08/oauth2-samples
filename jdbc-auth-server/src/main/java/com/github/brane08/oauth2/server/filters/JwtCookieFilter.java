package com.github.brane08.oauth2.server.filters;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.util.List;

public class JwtCookieFilter extends OncePerRequestFilter {
	private static final String SECRET_KEY = "XLxwEzxLmowhWCuOSzSQrm6GoI0PJFByD08n4XYs+f8XtZMh6ioy7fzzgmCRmjQK";
	private static final Logger logger = LoggerFactory.getLogger(JwtCookieFilter.class);
	private final String cookieName = "SSO_TOKEN";
	private JwtDecoder jwtDecoder;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
									FilterChain filterChain) throws ServletException, IOException {
		// Only attempt authentication if not already authenticated
		if (SecurityContextHolder.getContext().getAuthentication() == null) {

			String token = extractTokenFromCookie(request);

			if (token != null) {
				try {
					Jwt jwt = jwtDecoder().decode(token);

					// Simple authority mapping, customize based on your JWT claims
					SimpleGrantedAuthority authority = new SimpleGrantedAuthority("ROLE_USER");

					var auth = UsernamePasswordAuthenticationToken.authenticated(
							jwt.getSubject(),
							null,
							List.of(authority)
					);

					auth.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

					// Mark as authenticated
					SecurityContextHolder.getContext().setAuthentication(auth);

				} catch (JwtException ex) {
					// Invalid JWT: log and continue without authentication
					logger.warn("Invalid JWT in cookie '{}': {}", cookieName, ex.getMessage());
				}
			}
		}

		filterChain.doFilter(request, response);
	}

	private String extractTokenFromCookie(HttpServletRequest request) {
		if (request.getCookies() == null) return null;

		for (Cookie cookie : request.getCookies()) {
			if (cookieName.equals(cookie.getName())) {
				return cookie.getValue();
			}
		}
		return null;
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
