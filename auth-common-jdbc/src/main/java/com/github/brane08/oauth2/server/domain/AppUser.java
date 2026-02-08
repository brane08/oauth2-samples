package com.github.brane08.oauth2.server.domain;

import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.MappedCollection;
import org.springframework.data.relational.core.mapping.Table;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Objects;
import java.util.Set;

@Table("users")
public class AppUser {

    @Id
    private String username;
    private String password;
    private String email;
    private boolean enabled;
    private Instant lastUsed;
    @MappedCollection(keyColumn = "username", idColumn = "username")
    private Set<Authority> authorities;

    public AppUser(String username, String password, boolean enabled, Instant lastUsed) {
        this.username = username;
        this.password = password;
        this.enabled = enabled;
        this.lastUsed = lastUsed;
    }

    public static UserDetails toUserDetails(AppUser user) {
        User.UserBuilder builder = User.builder();
        builder.username(user.getUsername()).password(user.getPassword()).disabled(!user.isEnabled())
                .authorities(user.getAuthorities().stream()
                        .map(a -> new SimpleGrantedAuthority(a.getAuthority())).toList());
        return builder.build();

    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Instant getLastUsed() {
        return lastUsed;
    }

    public void setLastUsed(Instant lastUsed) {
        this.lastUsed = lastUsed;
    }

    public Set<Authority> getAuthorities() {
        return authorities;
    }

    public void setAuthorities(Set<Authority> authorities) {
        this.authorities = authorities;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AppUser appUser = (AppUser) o;
        return username.equals(appUser.username);
    }

    @Override
    public int hashCode() {
        return Objects.hash(username);
    }
}
