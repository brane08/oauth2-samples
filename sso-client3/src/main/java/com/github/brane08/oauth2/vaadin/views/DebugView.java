package com.github.brane08.oauth2.vaadin.views;

import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.router.Route;
import jakarta.annotation.security.PermitAll;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;

@Route("debug")
@PermitAll
public class DebugView extends VerticalLayout {
    public DebugView() {
        SecurityContext ctx = SecurityContextHolder.getContext();
        Authentication auth = ctx.getAuthentication();

        add(new H2("JWT Debug Info"));
        add(new Span("Principal: " + auth.getPrincipal()));
        add(new Span("Name: " + auth.getName()));
        add(new Span("Authorities: " + auth.getAuthorities()));

        if (auth.getPrincipal() instanceof Jwt jwt) {
            add(new Span("JWT Claims: " + jwt.getClaims()));
            add(new Span("JWT Scope: " + jwt.getClaimAsStringList("scope")));
        }
    }
}