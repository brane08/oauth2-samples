package com.github.brane08.oauth2.server.service;

import com.github.brane08.oauth2.server.domain.AppUser;
import com.github.brane08.oauth2.server.repository.AppUserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class LocalUserDetailsService implements UserDetailsService {

	private final AppUserRepository userRepository;

	public LocalUserDetailsService(AppUserRepository userRepository) {
		this.userRepository = userRepository;
	}


	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser user = userRepository.findAppUserByUsername(username)
				.orElseThrow(() -> new UsernameNotFoundException("Username not found"));
		return AppUser.toUserDetails(user);
	}
}
