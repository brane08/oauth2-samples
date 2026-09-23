package com.github.brane08.oauth2.sso;

import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.session.MapSessionRepository;

import java.util.concurrent.ConcurrentHashMap;

@SpringBootTest(properties = "spring.main.allow-bean-definition-overriding=true")
@Import(SsoGatewayMvcApplicationTests.NoTlsHttpClient.class)
class SsoGatewayMvcApplicationTests {

    @TestConfiguration
    static class NoTlsHttpClient {
        @Bean
        PoolingHttpClientConnectionManagerBuilder poolingHttpClientConnectionManager() {
            return PoolingHttpClientConnectionManagerBuilder.create();
        }

        @Bean
        MapSessionRepository mongoSessionRepository() {
            return new MapSessionRepository(new ConcurrentHashMap<>());
        }
    }

    @Test
    void contextLoads() {
    }

}
