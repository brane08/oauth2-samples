package com.github.brane08.service.mvc.service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final EntityManager em;

    public UserService(EntityManager em) {
        this.em = em;
    }

    public Long findByUsername(String username) {
        Query query = em.createNativeQuery("select count(username) from users", Long.class);
        return (Long) query.getSingleResult();
    }
}
