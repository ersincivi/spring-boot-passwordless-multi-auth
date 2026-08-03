package io.github.ersincivi.passwordless.dto;

import java.io.Serializable;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public class ForgotPasswordForm implements Serializable {

    @NotBlank(message = "{register.email.required}")
    @Email(message = "{register.email.invalid}")
    private String email;

    public ForgotPasswordForm() {
    }

     public ForgotPasswordForm(String email) {
        this.email = email;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

}
