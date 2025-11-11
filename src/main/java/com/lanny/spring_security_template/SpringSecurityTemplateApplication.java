package com.lanny.spring_security_template;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;

@SpringBootApplication
@EnableConfigurationProperties(SecurityJwtProperties.class)
public class SpringSecurityTemplateApplication {

  public static void main(String[] args) {
    SpringApplication.run(SpringSecurityTemplateApplication.class, args);
  }
}
