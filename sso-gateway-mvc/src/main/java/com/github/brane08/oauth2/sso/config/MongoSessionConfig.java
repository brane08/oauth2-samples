package com.github.brane08.oauth2.sso.config;

import com.github.brane08.oauth2.sso.client.MongoOAuth2AuthorizedClientService;
import com.mongodb.*;
import com.mongodb.client.MongoClient;
import com.mongodb.client.MongoClients;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.mongodb.core.MongoTemplate;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.session.data.mongo.config.annotation.web.http.EnableMongoHttpSession;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableMongoHttpSession(collectionName = "gateway_sessions", maxInactiveIntervalInSeconds = 3600)
public class MongoSessionConfig {

    @Bean
    public MongoClient mongoClient() {
        ConnectionString connString = new ConnectionString(
                "mongodb://prore:password@localhost:27017/sas?authSource=admin"
        );
        MongoClientSettings settings = MongoClientSettings.builder()
                .applyConnectionString(connString)
                .applyToConnectionPoolSettings(builder ->
                        builder.maxSize(50).minSize(10))  // Pool: max/min connections
                .applyToSocketSettings(builder ->
                        builder.connectTimeout(30_000, TimeUnit.MILLISECONDS)  // Connect timeout
                                .readTimeout(120_000, TimeUnit.MILLISECONDS))  // Socket timeout
                .retryWrites(true)  // Retry writes
                .readConcern(ReadConcern.MAJORITY)
                .readPreference(ReadPreference.primary())
                .writeConcern(WriteConcern.MAJORITY.withJournal(true))
                .build();
        return MongoClients.create(settings);
    }

    @Bean
    public MongoTemplate mongoTemplate(MongoClient mongoClient) {
        return new MongoTemplate(mongoClient, "sas");
    }

    @Bean
    public OAuth2AuthorizedClientService oAuth2AuthorizedClientService(MongoTemplate mongoTemplate,
                                                                       ClientRegistrationRepository clientRegistrationRepository) {
        return new MongoOAuth2AuthorizedClientService(mongoTemplate, clientRegistrationRepository);
    }
}
