package com.lanny.spring_security_template.application.auth.port.out;

public interface ChangePasswordPort {
    void changePassword(String username, String oldPassword, String newPassword);
}

