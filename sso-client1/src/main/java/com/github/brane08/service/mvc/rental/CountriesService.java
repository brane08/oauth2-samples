package com.github.brane08.service.mvc.rental;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;

@Service
public class CountriesService {

    private final CountriesRepository repository;

    public CountriesService(CountriesRepository repository) {
        this.repository = repository;
    }

    public Page<Country> findAllCountries(Pageable page) {
        return repository.findAll(page);
    }

    public Page<Country> findByCountryContainingIgnoreCase(String keyword, Pageable pageable) {
        return repository.findByCountryContainingIgnoreCase(keyword, pageable);
    }
}
