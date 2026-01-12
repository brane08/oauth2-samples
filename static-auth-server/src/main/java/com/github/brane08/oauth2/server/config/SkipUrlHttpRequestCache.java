package com.github.brane08.oauth2.server.config;

import com.github.brane08.oauth2.server.web.utils.RequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.util.matcher.RequestMatcher;

public class SkipUrlHttpRequestCache extends HttpSessionRequestCache {

	private static final Logger LOG = LoggerFactory.getLogger(SkipUrlHttpRequestCache.class);
	private final RequestMatcher requestMatcher = RequestUtils.getOauth2RequestMatcher();

	public SkipUrlHttpRequestCache() {
		super.setCreateSessionAllowed(true);
	}

	@Override
	public void saveRequest(HttpServletRequest req, HttpServletResponse res) {
		String uri = req.getRequestURI();
		if (!requestMatcher.matches(req)) {
			LOG.debug("Skip saving Redirect url: {}", uri);
			return;
		}
		LOG.debug("Saving request for URI: {}", uri);
		super.saveRequest(req, res);
	}
}
