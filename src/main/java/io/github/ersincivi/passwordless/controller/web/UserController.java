package io.github.ersincivi.passwordless.controller.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class UserController {

    @GetMapping("/dashboard")
    public String userHome() {
        return "user/index";
    }
}


