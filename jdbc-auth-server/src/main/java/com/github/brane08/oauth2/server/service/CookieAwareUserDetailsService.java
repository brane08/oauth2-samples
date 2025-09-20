package com.github.brane08.oauth2.server.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class CookieAwareUserDetailsService implements UserDetailsService {

	private static final Logger LOG = LoggerFactory.getLogger(CookieAwareUserDetailsService.class);

	private final UserDetailsService delegate;

	public CookieAwareUserDetailsService(UserDetailsService delegate) {
		this.delegate = delegate;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		LOG.debug("Attempting to load user by username {}", username);
		String actualUsername = username;
		if (username.startsWith("cookie:")) {
			actualUsername = username.substring("cookie:".length());
			LOG.info("Found cookie value as pre-authenticated");
		}
		return delegate.loadUserByUsername(actualUsername);
	}
}
