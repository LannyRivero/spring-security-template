package com.lanny.spring_security_template.infrastructure.security.ratelimit;

import org.springframework.stereotype.Component;

@Component
public class RateLimitKeyResolverFactory {

    private final IpUserRateLimitKeyResolver ipUserResolver;

    public RateLimitKeyResolverFactory(IpUserRateLimitKeyResolver ipUserResolver) {
        this.ipUserResolver = ipUserResolver;
    }

    public RateLimitKeyResolver get(String strategy) {
        return switch (strategy.toUpperCase()) {
            case "IP_USER" -> ipUserResolver;
            case "IP" -> req -> req.getRemoteAddr();
            case "USER" -> req -> req.getParameter("username") != null
                    ? req.getParameter("username")
                    : "anonymous";
            default -> req -> req.getRemoteAddr(); 
        };
    }
}
