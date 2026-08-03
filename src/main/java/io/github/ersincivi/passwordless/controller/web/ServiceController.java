package io.github.ersincivi.passwordless.controller.web;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ServiceController {

	@GetMapping("/service")
	public String serviceHome() {
		return "service/index";
	}
}


