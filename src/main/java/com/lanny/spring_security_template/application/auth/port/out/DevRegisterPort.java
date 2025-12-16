package com.lanny.spring_security_template.application.auth.port.out;

import com.lanny.spring_security_template.application.auth.command.RegisterCommand;

public interface DevRegisterPort {
    void register(RegisterCommand command);
}
