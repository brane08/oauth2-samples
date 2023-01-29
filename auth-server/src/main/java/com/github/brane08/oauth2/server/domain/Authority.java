package com.github.brane08.oauth2.server.domain;

import org.springframework.data.relational.core.mapping.Table;

import java.util.Objects;

@Table("authorities")
public class Authority {

	private String username;
	private String authority;

	public Authority(String username, String authority) {
		this.username = username;
		this.authority = authority;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getAuthority() {
		return authority;
	}

	public void setAuthority(String authority) {
		this.authority = authority;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		Authority authority1 = (Authority) o;
		return username.equals(authority1.username) && authority.equals(authority1.authority);
	}

	@Override
	public int hashCode() {
		return Objects.hash(username, authority);
	}
}
