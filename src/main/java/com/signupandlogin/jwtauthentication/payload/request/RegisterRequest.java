package com.signupandlogin.jwtauthentication.payload.request;

import com.signupandlogin.jwtauthentication.entity.Role;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class RegisterRequest {
    @NotBlank(message = "First name is Required")
    private String firstName;
    @NotBlank(message = "lastname is required")
    private String lastName;

    @Email(message = "Invalid email format")
    @NotBlank(message = "Email is required")
    private String email;

    @NotBlank
    @Size(min = 6, message = "Password is required")
    @Pattern(regexp = "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$", message = "Password must be at least 8 characters long, should have 1 uppercase letter, 1 lowercase letter, 1 number, and 1 special character")
    private String password;

    @NotNull(message = "Role is required")
    private Role role;

}
