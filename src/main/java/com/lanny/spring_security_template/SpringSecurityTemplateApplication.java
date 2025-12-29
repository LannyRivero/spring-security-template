package com.lanny.spring_security_template;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;

import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

@SpringBootApplication
public class SpringSecurityTemplateApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringSecurityTemplateApplication.class, args);
  }

  @Bean
  @Profile("!test")
  CommandLineRunner checkPrometheusRegistry(PrometheusMeterRegistry registry) {
    return args -> {
        System.out.println("✅ Prometheus registry loaded: " + registry.getClass().getName());
    };
  }

}
