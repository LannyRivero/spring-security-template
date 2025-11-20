package com.lanny.spring_security_template.application.auth.port.out;

import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;

public interface JwtValidator {
    JwtClaimsDTO validate(String token);
}
