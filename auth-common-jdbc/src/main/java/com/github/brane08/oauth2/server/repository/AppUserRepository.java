package com.github.brane08.oauth2.server.repository;

import com.github.brane08.oauth2.server.domain.AppUser;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface AppUserRepository extends CrudRepository<AppUser, String> {

    Optional<AppUser> findAppUserByUsername(String username);
}
