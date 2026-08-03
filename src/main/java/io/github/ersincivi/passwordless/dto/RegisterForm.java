package io.github.ersincivi.passwordless.dto;

import java.io.Serializable;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public class RegisterForm implements Serializable {

    @Size(min = 2, max = 100, message = "{register.name.size}")
    @NotBlank(message = "{register.name.required}")
    private String name;

    @NotBlank(message = "{register.email.required}")
    @Email(message = "{register.email.invalid}")
    private String email;

    // Thymeleaf form binding requires empty constructor
    public RegisterForm() {}

    public RegisterForm(String name, String email) {
        this.name = name;
        this.email = email;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @Override
    public String toString() {
        return "RegisterForm {" +
            "name='" + name + '\'' +
            ", email='" + email + '\'' +
        '}';
    }
}