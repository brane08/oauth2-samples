package com.github.brane08.service.webflux.rest;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

@RestController
@RequestMapping("/api")
public class HomeController {

    private final JsonMapper jsonMapper;

    public HomeController(JsonMapper jsonMapper) {
        this.jsonMapper = jsonMapper;
    }

    @GetMapping
    public JsonNode getSample() {
        return jsonMapper.createObjectNode().put("status", true).put("message", "This is default API of app2")
                .put("source", "App2");
    }
}
