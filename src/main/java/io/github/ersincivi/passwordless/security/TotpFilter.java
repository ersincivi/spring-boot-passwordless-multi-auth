package io.github.ersincivi.passwordless.security;

import io.github.ersincivi.passwordless.dto.projection.UserMfaProjection;
import io.github.ersincivi.passwordless.service.UserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

import java.io.IOException;

@Component
public class TotpFilter extends StaticResourceIgnoringFilter {

    public static final String SESSION_TOTP_OK = "TOTP_OK";

    private final UserService userService;

    public TotpFilter(UserService userService) {
        this.userService = userService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        String path = request.getRequestURI();

        // Exclude public paths, static resources, and TOTP-related endpoints
        if (path.startsWith("/api/") || path.startsWith("/login") || path.startsWith("/totp") ||
                path.startsWith("/geo") || path.startsWith("/error") || path.startsWith("/swagger") ||
                path.startsWith("/v3") || path.startsWith("/css/") || path.startsWith("/js/") ||
                path.startsWith("/images/")) {
            filterChain.doFilter(request, response);
            return;
        }

        // ONLY enforce TOTP if there's a pending authentication session
        // This filter should NOT check TOTP for already authenticated users
        if (request.getSession(false) != null) {
            Object pendingUsername = request.getSession(false).getAttribute("PENDING_USERNAME");

            if (pendingUsername != null) {
                // Check if TOTP verification has been completed
                Object totpOk = request.getSession(false).getAttribute(SESSION_TOTP_OK);
                boolean totpVerified = totpOk instanceof Boolean b && b;

                if (!totpVerified) {
                    // TOTP verification still required, redirect to TOTP page
                    response.sendRedirect("/totp");
                    return;
                }
            }
        }
        
        filterChain.doFilter(request, response);
    }
}
