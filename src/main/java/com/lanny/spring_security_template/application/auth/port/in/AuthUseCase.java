package com.lanny.spring_security_template.application.auth.port.in;

import com.lanny.spring_security_template.auth.dto.JwtResponse;
import com.lanny.spring_security_template.auth.dto.LoginRequest;
import com.lanny.spring_security_template.auth.dto.MeResponse;
import com.lanny.spring_security_template.auth.dto.RefreshRequest;

public interface AuthUseCase {
    JwtResponse login(LoginRequest request);

    JwtResponse refresh(RefreshRequest request);

    MeResponse me(String username);
}
