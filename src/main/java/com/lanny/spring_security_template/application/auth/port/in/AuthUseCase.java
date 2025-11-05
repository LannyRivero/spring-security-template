package com.lanny.spring_security_template.application.auth.port.in;

import com.lanny.spring_security_template.application.auth.command.*;
import com.lanny.spring_security_template.application.auth.result.*;

public interface AuthUseCase {
    JwtResult login(LoginCommand command);

    JwtResult refresh(RefreshCommand command);

    MeResult me(String username);
}
