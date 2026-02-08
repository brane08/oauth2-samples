package com.github.brane08.service.mvc.rest;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.brane08.pagila.contries.CountriesService;
import com.github.brane08.pagila.contries.Country;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class HomeController {

    private final ObjectMapper jsonMapper;
    private final CountriesService service;

    public HomeController(ObjectMapper jsonMapper, CountriesService service) {
        this.jsonMapper = jsonMapper;
        this.service = service;
    }

    @GetMapping
    public JsonNode getSample() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return jsonMapper.createObjectNode().put("status", true).put("message", "This is default API of app1")
                .put("source", "App1").put("reqestedBy", authentication.getName());
    }

    @PostMapping("/countries")
    public Page<Country> postSample() {
        Pageable pageable = PageRequest.of(0, 10, Sort.by("name").descending());
        return service.findAllCountries(pageable);
    }
}
