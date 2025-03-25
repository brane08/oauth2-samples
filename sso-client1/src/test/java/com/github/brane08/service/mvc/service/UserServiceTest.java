package com.github.brane08.service.mvc.service;

import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    EntityManager entityManager;
    @Mock
    Query query;
    UserService userService;

    @BeforeEach
    void setUp() {
        userService = new UserService(entityManager);
    }

    @Test
    void testFindByUsername() {
        when(entityManager.createNativeQuery(anyString(), eq(Long.class))).thenReturn(query);
        when(query.getSingleResult()).thenReturn(1L);
        userService.findByUsername("admin");
    }
}