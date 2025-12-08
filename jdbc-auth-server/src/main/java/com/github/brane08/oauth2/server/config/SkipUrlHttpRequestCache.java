package com.github.brane08.oauth2.server.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;

public class SkipUrlHttpRequestCache extends HttpSessionRequestCache {

	@Override
	public void saveRequest(HttpServletRequest req, HttpServletResponse res) {
		String uri = req.getRequestURI();
		if ("/".equals(uri) || "/login".equals(uri)) {
			return; // don’t save /login — avoids loops
		}
		super.saveRequest(req, res);
	}
}
