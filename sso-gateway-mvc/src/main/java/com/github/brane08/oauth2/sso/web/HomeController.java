package com.github.brane08.oauth2.sso.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;

import java.time.LocalDate;

@Controller
public class HomeController {

    @ModelAttribute("year")
    public String yearAttribute() {
        return Integer.toString(LocalDate.now().getYear());
    }

    @GetMapping("/home")
    public String home() {
        return "home";
    }

    @GetMapping("/about")
    public String about() {
        return "about";
    }
}
