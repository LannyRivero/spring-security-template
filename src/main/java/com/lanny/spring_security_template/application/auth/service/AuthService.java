package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.web.dto.AuthRequest;
import com.lanny.spring_security_template.web.dto.AuthResponse;
import com.lanny.spring_security_template.web.dto.RegisterRequest;

import org.springframework.stereotype.Service;

@Service
public class AuthService implements AuthUseCase {

    @Override
    public AuthResponse login(AuthRequest request) {
        // TODO: Implement JWT authentication (Phase F2)
        return new AuthResponse("dummy-access-token", "dummy-refresh-token");
    }

    @Override
    public AuthResponse register(RegisterRequest request) {
        // TODO: Implement user registration (Phase F2)
        return new AuthResponse("dummy-access-token", "dummy-refresh-token");
    }    
}

