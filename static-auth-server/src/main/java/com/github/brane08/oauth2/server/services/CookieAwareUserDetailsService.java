package com.github.brane08.oauth2.server.services;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

public class CookieAwareUserDetailsService implements UserDetailsService {

	private static final Logger LOG = LoggerFactory.getLogger(CookieAwareUserDetailsService.class);

	private final UserDetailsService delegate;
	private final PasswordEncoder passwordEncoder;

	public CookieAwareUserDetailsService(UserDetailsService delegate, PasswordEncoder passwordEncoder) {
		this.delegate = delegate;
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		LOG.debug("Attempting to load user by username {}", username);
		if (username.startsWith("cookie:")) {
			String actualUsername = username.substring("cookie:".length());
			LOG.info("Found cookie value as pre-authenticated");
			return User.withUsername(actualUsername)
					.password(passwordEncoder.encode("placeholder"))
					.roles("USER")
					.build();
		}
		return delegate.loadUserByUsername(username);
	}
}
