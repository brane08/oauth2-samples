package com.github.brane08.service.mvc.rental;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface CountriesRepository extends PagingAndSortingRepository<Country, Integer> {

    Page<Country> findByCountryContainingIgnoreCase(String keyword, Pageable pageable);
}
