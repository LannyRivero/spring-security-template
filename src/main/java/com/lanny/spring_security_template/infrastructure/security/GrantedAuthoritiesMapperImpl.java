package com.lanny.spring_security_template.infrastructure.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import java.util.Collection;
import java.util.stream.Collectors;

@Configuration
public class GrantedAuthoritiesMapperImpl {
    @Bean
    public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        return (Collection<? extends GrantedAuthority> authorities) -> authorities.stream()
                .map(a -> (GrantedAuthority) () -> {
                    String au = a.getAuthority();
                    if (au.startsWith("ROLE_") || au.startsWith("SCOPE_"))
                        return au;
                    if (au.contains(":"))
                        return "SCOPE_" + au; 
                    return "ROLE_" + au;
                }).collect(Collectors.toSet());
    }
}
