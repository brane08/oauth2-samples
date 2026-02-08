package com.github.brane08.oauth2.vaadin.views;

import com.vaadin.flow.component.button.Button;
import com.vaadin.flow.component.notification.Notification;
import com.vaadin.flow.component.orderedlayout.HorizontalLayout;
import com.vaadin.flow.component.textfield.TextField;

public class HelloWorldView extends HorizontalLayout {
    private TextField name;
    private Button sayHello;

    public HelloWorldView() {
        setId("hello-world-view");
        name = new TextField("Your name");
        sayHello = new Button("Say hello");
        add(name, sayHello);
        setVerticalComponentAlignment(Alignment.END, name, sayHello);

        // Handle clicks
        sayHello.addClickListener(e -> {
            Notification.show("Hello " + name.getValue());
        });
    }

}