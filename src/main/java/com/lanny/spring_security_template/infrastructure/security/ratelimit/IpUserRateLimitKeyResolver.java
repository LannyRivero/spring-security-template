package com.lanny.spring_security_template.infrastructure.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

@Component
public class IpUserRateLimitKeyResolver implements RateLimitKeyResolver {

    @Override
    public String resolveKey(HttpServletRequest request) {
        String ip = request.getRemoteAddr();
        String username = request.getParameter("username");
        if (username == null || username.isBlank()) {
            username = "anonymous";
        }
        return ip + "|" + username;
    }
}

