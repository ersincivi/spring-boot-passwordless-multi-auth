package io.github.ersincivi.passwordless.controller.web;

import org.springframework.stereotype.Component;

/**
 * TODO: Spring Boot 4 Migration
 * 
 * Spring Boot 4 now provides BasicErrorController by default.
 * This custom error controller has been disabled to avoid mapping conflicts
 * with the auto-configured error handling.
 * 
 * To customize error pages in Spring Boot 4, use one of these approaches:
 * 
 * 1. Create error templates in src/main/resources/templates/error/
 *    - error/404.html, error/500.html, etc.
 *    - error.html (fallback for all errors)
 * 
 * 2. Extend BasicErrorController and override methods:
 *    @Controller
 *    public class CustomErrorController extends BasicErrorController {
 *        // Override methods as needed
 *    }
 * 
 * 3. Implement ErrorController interface with a different path:
 *    @Controller
 *    @RequestMapping("/custom-error")
 *    public class CustomErrorController implements ErrorController {
 *        // Custom error handling
 *    }
 * 
 * This placeholder class is kept to maintain bean dependencies
 * until the migration is fully complete.
 */
@Component
public class WebErrorController {
    
    public WebErrorController(org.springframework.core.env.Environment env) {
        // Disabled - using Spring Boot 4's default error handling
        // The BasicErrorController is auto-configured by Spring Boot
    }
}
