package com.github.brane08.oauth2.vaadin.views;

import com.vaadin.flow.component.applayout.AppLayout;
import com.vaadin.flow.component.applayout.DrawerToggle;
import com.vaadin.flow.component.html.H1;
import com.vaadin.flow.component.html.H2;
import com.vaadin.flow.component.html.Span;
import com.vaadin.flow.component.orderedlayout.FlexComponent;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.orderedlayout.VerticalLayout;
import com.vaadin.flow.component.tabs.Tab;
import com.vaadin.flow.component.tabs.Tabs;
import com.vaadin.flow.router.PageTitle;
import com.vaadin.flow.router.Route;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;

@Route("")
@PageTitle("OAuth2 Vaadin Resource Server")
@RolesAllowed("USER")
public class IndexView extends AppLayout {

    public IndexView() {
        // Navbar: Toggle + Title
        DrawerToggle toggle = new DrawerToggle();
        HorizontalLayout header = new HorizontalLayout(
                toggle,
                new H1("OAuth2 Resource Server Demo")
        );
        header.setAlignItems(FlexComponent.Alignment.CENTER);
        header.setWidthFull();
        header.expand(header.getComponentAt(1));

        addToNavbar(header);

        // Drawer: Menu + Footer
        VerticalLayout drawer = new VerticalLayout();
        drawer.setPadding(true);
        drawer.setSpacing(true);
        drawer.setSizeFull();

        // Menu tabs
        Tabs tabs = new Tabs(
                new Tab("Dashboard"),
                new Tab("Users"),
                new Tab("Settings"),
                new Tab("Logout")
        );
        tabs.setOrientation(Tabs.Orientation.VERTICAL);
        tabs.setWidthFull();
        drawer.add(tabs);

        // Footer
        HorizontalLayout footer = new HorizontalLayout(
                new Span("© 2026 OAuth2 Vaadin Demo"),
                new Span("Built with Vaadin")
        );
        footer.setWidthFull();
        footer.setJustifyContentMode(FlexComponent.JustifyContentMode.CENTER);
        drawer.add(footer);

        addToDrawer(drawer);

        // Main content area
        VerticalLayout mainContent = new VerticalLayout();
        mainContent.setPadding(true);
        mainContent.setAlignItems(FlexComponent.Alignment.CENTER);
        mainContent.add(
                new H2("Welcome to the landing page!"),
                new Span("Your OAuth2 resource server is working.")
        );
        setContent(mainContent);
    }
}

