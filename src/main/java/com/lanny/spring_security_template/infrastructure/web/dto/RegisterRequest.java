package com.lanny.spring_security_template.infrastructure.web.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;

/**
 * Data Transfer Object for user registration requests.
 * 
 * @param username the desired username.
 * @param password the desired password.
 * @param email    the user's email address.
 */

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest implements CredentialsRequest {

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    String username;

    @NotBlank(message = "Password is required")
    @Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
    String password;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    String email;
}
