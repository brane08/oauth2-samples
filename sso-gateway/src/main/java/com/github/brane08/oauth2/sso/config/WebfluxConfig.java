package com.github.brane08.oauth2.sso.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsWebFilter;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;
import org.springframework.web.reactive.config.ViewResolverRegistry;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.result.view.freemarker.FreeMarkerConfigurer;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

@Configuration(proxyBeanMethods = false)
public class WebfluxConfig {

	private final List<String> staticPaths = List.of("/**/*.css", "/**/*.js", "/**/*.map", "/**/*.html", "/**/*.wasm",
			"/**/*.png", "/**/*.jpg", "/**/*.jpeg", "/**/*.svg", "/**/*.ico", "/**/*.gif", "/**/*.woff", "/**/*.woff2",
			"/**/*.ttf", "/**/*.eot", "/assets/**");

	@Bean
	WebFluxConfigurer webFluxConfigurer() {
		return new WebFluxConfigurer() {
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
	public CorsWebFilter corsWebFilter() {
		CorsConfiguration config=new CorsConfiguration();
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
		UrlBasedCorsConfigurationSource source=new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**",config);
		return new CorsWebFilter(source);
	}

	@Bean
	public ServerWebExchangeMatcher staticResourcesMatcher() {
		return new OrServerWebExchangeMatcher(getRequestMatchers(staticPaths));
	}

	List<ServerWebExchangeMatcher> getRequestMatchers(List<String> paths) {
		List<ServerWebExchangeMatcher> requestMatchers = new ArrayList<>();
		for (String path : paths) {
			requestMatchers.add(new PathPatternParserServerWebExchangeMatcher(path));
		}
		return  requestMatchers;
	}
}
