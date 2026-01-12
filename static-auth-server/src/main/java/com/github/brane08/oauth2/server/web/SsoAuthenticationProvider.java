package com.github.brane08.oauth2.server.web;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;

@Component
public class SsoAuthenticationProvider implements AuthenticationProvider {

	private final UserDetailsService userDetailsService;

	public SsoAuthenticationProvider(UserDetailsService userDetailsService) {
		this.userDetailsService = userDetailsService;
	}

	@Override
	public Authentication authenticate(Authentication authentication) {
		String ssoValue = (String) authentication.getPrincipal();
		UserDetails details = userDetailsService.loadUserByUsername(ssoValue);
		return new UsernamePasswordAuthenticationToken(details, null, details.getAuthorities());
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
	}
}
