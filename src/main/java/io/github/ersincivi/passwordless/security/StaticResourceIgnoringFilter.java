package io.github.ersincivi.passwordless.security;

import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;

public abstract class StaticResourceIgnoringFilter extends OncePerRequestFilter {

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();
        // Shared skip rules for all filters
        return path.startsWith("/css") || 
               path.startsWith("/js") || 
               path.startsWith("/images") ||
               path.equals("/favicon.ico");
    }

    // Note: doFilterInternal stays abstract and is not implemented in this class
}
