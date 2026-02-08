package com.github.brane08.oauth2.vaadin.config;

import com.vaadin.flow.component.page.AppShellConfigurator;
import com.vaadin.flow.component.page.Meta;
import com.vaadin.flow.component.page.Push;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.shared.communication.PushMode;
import org.springframework.context.annotation.Configuration;

@Configuration
@Push(PushMode.DISABLED)
@PageTitle("SSO Vaadin Client")
@Meta(name="description", content="OAuth2 Vaadin Demo")
public class AppShellConfig implements AppShellConfigurator {
    // Empty: handles global @Push
}