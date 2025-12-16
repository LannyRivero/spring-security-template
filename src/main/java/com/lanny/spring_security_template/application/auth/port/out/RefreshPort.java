package com.lanny.spring_security_template.application.auth.port.out;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.result.JwtResult;

public interface RefreshPort {
    JwtResult refresh(RefreshCommand command);
}
