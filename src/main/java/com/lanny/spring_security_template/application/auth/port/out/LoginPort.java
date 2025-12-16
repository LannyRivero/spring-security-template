package com.lanny.spring_security_template.application.auth.port.out;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.result.JwtResult;

public interface LoginPort {
    JwtResult login(LoginCommand command);
}
