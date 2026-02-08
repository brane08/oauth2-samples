package com.github.brane08.oauth2.vaadin.config;

import com.github.brane08.pagila.contries.CountriesRepository;
import com.github.brane08.pagila.contries.CountriesService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ServicesConfig {

    @Bean
    public CountriesService countriesService(CountriesRepository repository) {
        return new CountriesService(repository);
    }
}
