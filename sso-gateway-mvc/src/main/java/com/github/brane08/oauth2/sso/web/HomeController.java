package com.github.brane08.oauth2.sso.web;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestParam;

import java.net.URI;
import java.time.LocalDate;

@Controller
public class HomeController {

    private static final Logger LOG = LoggerFactory.getLogger(HomeController.class);

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

    @GetMapping("/")
    public String handleRoot(@RequestParam(required = false) String redirect,
                             HttpServletResponse res) {
        LOG.debug("Handling root request, redirect param: {}", redirect);
        if (redirect != null) {
            LOG.debug("Handling root request, redirect param: {}", redirect);
            return "forward:" + redirect;
        }
        return "index";
    }
}
