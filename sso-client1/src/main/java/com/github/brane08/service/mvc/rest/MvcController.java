package com.github.brane08.service.mvc.rest;

import com.github.brane08.service.mvc.rental.CountriesService;
import com.github.brane08.service.mvc.rental.Country;
import com.github.brane08.service.mvc.rental.CountryFilter;
import io.github.wimdeblauwe.htmx.spring.boot.mvc.HxRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.web.PageableDefault;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.servlet.view.FragmentsRendering;

@Controller
public class MvcController {

    private final CountriesService service;

    public MvcController(CountriesService service) {
        this.service = service;
    }

    @GetMapping("/")
    public String index(Model model) {
        model.addAttribute("filter", new CountryFilter());
        return "index";
    }

    @HxRequest
    @PostMapping("/countries/search")  // Or @GetMapping for bookmarkable
    public FragmentsRendering searchCountries(@ModelAttribute CountryFilter filter,
                                              @PageableDefault(size = 10, sort = "country") Pageable pageable,
                                              Model model) {
        Pageable appliedPageable = PageRequest.of(
                filter.getPage() > 0 ? filter.getPage() - 1 : 0,
                filter.getSize(), pageable.getSort());

        Page<Country> countries = filter.getKeyword() != null
                ? service.findByCountryContainingIgnoreCase(filter.getKeyword(), appliedPageable)
                : service.findAllCountries(appliedPageable);

        model.addAttribute("countries", countries);
        model.addAttribute("filter", filter);

        return FragmentsRendering
                .fragment("fragments/countries :: table(countries)")
                .fragment("fragments/countries :: pagination(countries, filter)")
                .build();
    }

    @GetMapping("/countries")  // Initial page load
    public String countriesPage(Model model) {
        model.addAttribute("filter", new CountryFilter());
        return "countries/index";  // Full page
    }
}
