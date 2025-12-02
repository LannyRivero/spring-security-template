package com.lanny.spring_security_template.infrastructure.http;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class HttpClientConfig {

    @Bean
    public RestTemplate safeRestTemplate() {
        RestTemplate template = new RestTemplate();
        // Aquí se pueden agregar timeouts, interceptores, logging, etc.
        return template;
    }
}

