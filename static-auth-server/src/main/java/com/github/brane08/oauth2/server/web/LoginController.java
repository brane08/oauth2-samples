package com.github.brane08.oauth2.server.web;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

import java.io.IOException;

@Controller
public class LoginController {

	private static final Logger LOG = LoggerFactory.getLogger(LoginController.class);

	private final AuthenticationManager authenticationManager;
	private final AuthenticationSuccessHandler successHandler = new SavedRequestAwareAuthenticationSuccessHandler();
	private final HttpSessionSecurityContextRepository contextRepository = new HttpSessionSecurityContextRepository();
	private final HttpSessionRequestCache requestCache = new HttpSessionRequestCache();

	public LoginController(AuthenticationManager authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

	@GetMapping("/login")
	public String loginPage(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String sso = readCookie(request, "SSO_TOKEN");  // HttpOnly is fine here
		if (sso != null && !sso.isBlank()) {
			// TODO: validate/parse JWT here and derive username
			LOG.debug("SSO Token found: {}", sso);
			UsernamePasswordAuthenticationToken authReq =
					new UsernamePasswordAuthenticationToken("cookie:" + sso, "placeholder");
			Authentication auth = authenticationManager.authenticate(authReq);
			SecurityContext context = SecurityContextHolder.createEmptyContext();
			context.setAuthentication(auth);
			SecurityContextHolder.setContext(context);
			LOG.debug("Security context is set for: {}", sso);
			contextRepository.saveContext(context, request, response);
			// If the saved request has been polluted to /login, drop it so we don’t loop
			SavedRequest saved = requestCache.getRequest(request, response);
			if (saved != null) {
				String target = saved.getRedirectUrl();
				if (target != null && !target.contains("/login")) {
					response.sendRedirect(target);
					return null;
				}
				// if polluted with /login, drop it
				requestCache.removeRequest(request, response);
			}

			// No saved request: go somewhere safe (NOT /oauth2/authorize without params)
			response.sendRedirect("/home");
//			SavedRequestAwareAuthenticationSuccessHandler success = new SavedRequestAwareAuthenticationSuccessHandler();
//			success.setDefaultTargetUrl("/oauth2/authorize");         // <- safe fallback
//			success.setUseReferer(false);
//			success.onAuthenticationSuccess(request, response, auth);
			return null;
		}
		return "login";
	}

	private static String readCookie(HttpServletRequest req, String name) {
		if (req.getCookies() == null) return null;
		for (Cookie c : req.getCookies()) if (name.equals(c.getName())) return c.getValue();
		return null;
	}
}
