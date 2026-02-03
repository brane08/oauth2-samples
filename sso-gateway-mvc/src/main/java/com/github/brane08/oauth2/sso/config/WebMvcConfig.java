package com.github.brane08.oauth2.sso.config;

import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClientBuilder;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.*;
import org.apache.hc.core5.pool.PoolReusePolicy;
import org.apache.hc.core5.ssl.SSLContexts;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.support.AbstractBeanFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Scope;
import org.springframework.http.client.ClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.ViewResolverRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.view.freemarker.FreeMarkerConfigurer;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

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

    @Bean
    PoolingHttpClientConnectionManagerBuilder poolingHttpClientConnectionManager(@Value("${server.ssl.trust-store}") String trustStore,
                                                                                 @Value("${server.ssl.trust-store-password}") String password) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, KeyManagementException {
        SSLContext sslContext = SSLContexts.custom()
                .loadTrustMaterial(new File(trustStore), password.toCharArray())
                .build();
        DefaultClientTlsStrategy tlsSocketStrategy = new DefaultClientTlsStrategy(sslContext, NoopHostnameVerifier.INSTANCE);
        return PoolingHttpClientConnectionManagerBuilder.create()
                .setTlsSocketStrategy(tlsSocketStrategy)
                .setMaxConnTotal(200)  // Total max connections
                .setMaxConnPerRoute(20)  // Max per route/peer
                .setConnPoolPolicy(PoolReusePolicy.LIFO)
                .setDefaultConnectionConfig(ConnectionConfig.custom().setConnectTimeout(Timeout.ofSeconds(30)).build());
    }


    HttpClientBuilder httpClientBuilder(PoolingHttpClientConnectionManagerBuilder connectionManagerBuilder) {
        return HttpClients.custom()
                .setDefaultRequestConfig(RequestConfig.custom().setResponseTimeout(Timeout.ofMinutes(2)).build())
                .setConnectionManager(connectionManagerBuilder.build())
                .evictExpiredConnections()
                .evictIdleConnections(TimeValue.of(2, TimeUnit.MINUTES));

    }

    @Bean
    RestTemplate restTemplate(PoolingHttpClientConnectionManagerBuilder connectionManagerBuilder)  {
        return new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClientBuilder(connectionManagerBuilder).build()));
    }
}
