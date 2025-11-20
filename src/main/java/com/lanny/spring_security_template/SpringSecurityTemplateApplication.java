package com.lanny.spring_security_template;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;

import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

@SpringBootApplication
@EnableConfigurationProperties({SecurityJwtProperties.class, RateLimitingProperties.class})

public class SpringSecurityTemplateApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringSecurityTemplateApplication.class, args);
  }

  @Bean
  CommandLineRunner checkPrometheusRegistry(PrometheusMeterRegistry registry) {
    return args -> {
        System.out.println("✅ Prometheus registry loaded: " + registry.getClass().getName());
    };
  }

}
