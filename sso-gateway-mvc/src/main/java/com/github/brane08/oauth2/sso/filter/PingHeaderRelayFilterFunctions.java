package com.github.brane08.oauth2.sso.filter;

import jakarta.servlet.http.Cookie;
import org.springframework.cloud.gateway.server.mvc.filter.SimpleFilterSupplier;
import org.springframework.web.servlet.function.HandlerFilterFunction;
import org.springframework.web.servlet.function.ServerRequest;
import org.springframework.web.servlet.function.ServerResponse;

/**
 * Forwards the pre-auth identity header and the gateway's SSO session cookie to the routed
 * backend, in place of {@code TokenRelay=} for routes running under the {@code ping-preauth}
 * profile (no OAuth2AuthorizedClient exists to relay a bearer token from in that mode).
 */
public final class PingHeaderRelayFilterFunctions {

    public static final String PING_USER_HEADER = "Sm_user";
    public static final String SSO_COOKIE_NAME = "GATEWAY_SSO";

    private PingHeaderRelayFilterFunctions() {
    }

    public static HandlerFilterFunction<ServerResponse, ServerResponse> pingHeaderRelay() {
        return (request, next) -> {
            ServerRequest.Builder builder = ServerRequest.from(request);

            String user = request.headers().firstHeader(PING_USER_HEADER);
            if (user != null) {
                builder.header(PING_USER_HEADER, user);
            }

            Cookie[] cookies = request.servletRequest().getCookies();
            if (cookies != null) {
                for (Cookie cookie : cookies) {
                    if (SSO_COOKIE_NAME.equals(cookie.getName())) {
                        builder.header("Cookie", SSO_COOKIE_NAME + "=" + cookie.getValue());
                    }
                }
            }

            return next.handle(builder.build());
        };
    }

    public static class FilterSupplier extends SimpleFilterSupplier {
        public FilterSupplier() {
            super(PingHeaderRelayFilterFunctions.class);
        }
    }
}
