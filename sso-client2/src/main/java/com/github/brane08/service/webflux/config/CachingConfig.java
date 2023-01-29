package com.github.brane08.service.webflux.config;

import org.springframework.cache.annotation.CachingConfigurer;
import org.springframework.cache.jcache.config.JCacheConfigurer;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CachingConfig implements CachingConfigurer {
}
