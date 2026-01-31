package com.github.brane08.oauth2.sso.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.ViewResolverRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.view.freemarker.FreeMarkerConfigurer;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Configuration(proxyBeanMethods = false)
public class WebMvcConfig {

    private final List<String> staticPaths = List.of("/**/*.css", "/**/*.js", "/**/*.map", "/**/*.html", "/**/*.wasm",
            "/**/*.png", "/**/*.jpg", "/**/*.jpeg", "/**/*.svg", "/**/*.ico", "/**/*.gif", "/**/*.woff", "/**/*.woff2",
            "/**/*.ttf", "/**/*.eot", "/assets/**");

    @Bean
    public WebMvcConfigurer webMvcConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void configureViewResolvers(ViewResolverRegistry registry) {
                registry.freeMarker();
            }
        };
    }

    @Bean
    public FreeMarkerConfigurer freeMarkerConfigurer() {
        FreeMarkerConfigurer configurer = new FreeMarkerConfigurer();
        configurer.setTemplateLoaderPath("classpath:/templates");
        return configurer;
    }


    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.addAllowedOriginPattern("https://*.example.com");
        config.setAllowCredentials(true);
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        config.addExposedHeader("Set-Cookie");
        config.addExposedHeader("X-CSRF-TOKEN");
        config.addExposedHeader("CSRF-TOKEN");
        config.addExposedHeader("Content-Type");
        config.addExposedHeader("Authorization");
        config.addExposedHeader("Location");
        config.addExposedHeader("Content-Length");
        config.addExposedHeader("Content-Disposition");
        config.addExposedHeader("WWW-Authenticate");
        config.setMaxAge(Duration.ofMinutes(60));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public RequestMatcher staticResourcesMatcher() {
        return new OrRequestMatcher(getRequestMatchers(staticPaths));
    }

    List<RequestMatcher> getRequestMatchers(List<String> paths) {
        List<RequestMatcher> requestMatchers = new ArrayList<>();
        for (String path : paths) {
            requestMatchers.add(PathPatternRequestMatcher.withDefaults().matcher(path));
        }
        return requestMatchers;
    }
}
