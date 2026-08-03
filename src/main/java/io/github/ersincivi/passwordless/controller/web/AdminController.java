package io.github.ersincivi.passwordless.controller.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class AdminController {

    @GetMapping("/admin")
    public String adminHome() {
        return "admin/index";
    }

    @GetMapping("/admin/users")
    public String adminUsers() {
        return "admin/users";
    }
}


