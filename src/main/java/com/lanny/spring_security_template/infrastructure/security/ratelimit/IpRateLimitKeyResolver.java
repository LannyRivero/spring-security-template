package com.lanny.spring_security_template.infrastructure.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.infrastructure.security.network.ClientIpResolver;

/**
 * Rate limiting based solely on resolved client IP address.
 */
@Component
public class IpRateLimitKeyResolver implements RateLimitKeyResolver {

    private static final String KEY_PREFIX = "security:ratelimit:v1:ip:";

    private final ClientIpResolver ipResolver;

    public IpRateLimitKeyResolver(ClientIpResolver ipResolver) {
        this.ipResolver = ipResolver;
    }

    @Override
    public String resolveKey(HttpServletRequest request) {
        return KEY_PREFIX + ipResolver.resolve(request);
    }
}
