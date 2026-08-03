package io.github.ersincivi.passwordless.config;

import io.github.ersincivi.passwordless.security.JwtAuthenticationFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseCookie.ResponseCookieBuilder;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.List;
import java.util.function.Consumer;

import io.github.ersincivi.passwordless.security.TotpFilter;
import io.github.ersincivi.passwordless.security.MagicLinkAuthenticationProvider;
import io.github.ersincivi.passwordless.security.MagicLinkAuthenticationFilter;
import org.springframework.beans.factory.annotation.Value;
import java.util.Arrays;
// Add imports for OAuth2 user service
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import io.github.ersincivi.passwordless.service.CustomOidcUserService;

import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.CsrfTokenRequestAttributeHandler;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.session.security.SpringSessionBackedSessionRegistry;
import org.springframework.session.FindByIndexNameSessionRepository;
import org.springframework.session.Session;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.session.SessionInformationExpiredStrategy;
import org.springframework.security.web.session.SimpleRedirectSessionInformationExpiredStrategy;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import io.github.ersincivi.passwordless.security.AuthenticationFailureHandler;
import io.github.ersincivi.passwordless.security.AuthenticationSuccessHandler;
import io.github.ersincivi.passwordless.security.EnhancedCsrfFilter;

import java.time.Duration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.web.servlet.ServletListenerRegistrationBean;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private static final org.slf4j.Logger log = org.slf4j.LoggerFactory.getLogger(SecurityConfig.class);

    @Autowired
    private UserDetailsService userDetailsService;

    // Inject our new custom MagicLink provider
    @Autowired
    private MagicLinkAuthenticationProvider magicLinkAuthenticationProvider;

    /**
     * T5.4: Redis-backed session registry. The default in-memory
     * SessionRegistryImpl loses all session knowledge on restart (and does not
     * share it across nodes). With Spring Session Data Redis active,
     * SpringSessionBackedSessionRegistry reads session data from Redis, so
     * concurrent-session control keeps working across restarts.
     */
    @Bean
    public SessionRegistry sessionRegistry(FindByIndexNameSessionRepository<? extends Session> sessionRepository) {
        return new SpringSessionBackedSessionRegistry<>(sessionRepository);
    }

    @Bean
    public HttpSessionEventPublisher httpSessionEventPublisher() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    public ServletListenerRegistrationBean<HttpSessionEventPublisher> httpSessionEventPublisherRegistration() {
        return new ServletListenerRegistrationBean<>(httpSessionEventPublisher());
    }

    @Bean
    public SessionInformationExpiredStrategy expiredSessionStrategy() {
        return new SimpleRedirectSessionInformationExpiredStrategy("/login?expired");
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // ==================== Beans ====================

    /**
     * ✅ RE-INTRODUCED: AuthenticationManager bean
     * 
     * LSP Compliance: The AuthenticationManager is the central "delegator" for ALL
     * authentication types, including OAuth2 and our new MagicLink provider.
     * 
     * This bean is *required* for our custom filter to work.
     * Getting it from AuthenticationConfiguration *does not* re-add
     * password support. It just wires up the existing providers (like the
     * one for OAuth2) and any custom ones we register (like MagicLink).
     * 
     * The AuthenticationManager delegates to registered AuthenticationProviders:
     * - OAuth2LoginAuthenticationProvider (for OAuth2/OIDC flows)
     * - MagicLinkAuthenticationProvider (for MagicLink flows)
     * 
     * This restores the Liskov Substitution Principle by ensuring all
     * authentication flows converge at the same delegation point.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
            throws Exception {
        log.info("AuthenticationManager bean created for LSP-compliant authentication flows");
        return authenticationConfiguration.getAuthenticationManager();
    }

    /**
     * Creates the MagicLinkAuthenticationFilter bean.
     * 
     * LSP Compliance: This filter uses the *same* success/failure handlers as all
     * other authentication flows (OAuth2, OIDC). This ensures:
     * - GeoIpService runs for MagicLink logins
     * - AccountLockoutService clears failed attempts
     * - SecurityAuditService logs authentication events
     * - Remember-me service can be configured
     * 
     * We inject the AuthenticationManager and our *existing* handlers.
     */
    @Bean
    public MagicLinkAuthenticationFilter magicLinkAuthenticationFilter(
            AuthenticationManager authenticationManager,
            AuthenticationSuccessHandler authenticationSuccessHandler, // Your existing handler
            AuthenticationFailureHandler authenticationFailureHandler  // Your existing handler
    ) {
        MagicLinkAuthenticationFilter filter = new MagicLinkAuthenticationFilter(authenticationManager);

        // THIS IS THE KEY:
        // We tell the filter to use the *same* handlers as all other login flows.
        // Now your GeoIpService and other logic will run automatically!
        filter.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        filter.setAuthenticationFailureHandler(authenticationFailureHandler);
      
        log.info("MagicLinkAuthenticationFilter bean created with unified success/failure handlers");

        return filter;
    }

    @Bean
    public LogoutSuccessHandler logoutSuccessHandler() {
        return (request, response, authentication) -> {
            String user = authentication != null ? authentication.getName() : "anonymous";
            org.slf4j.LoggerFactory.getLogger("security").info("logout.success user={}", user);
            response.sendRedirect("/login?logout");
        };
    }

    // API LOGIN FILTER CHAIN
    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http, JwtAuthenticationFilter jwtAuthenticationFilter)
            throws Exception {
        http
                .securityMatcher("/api/**")
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                .ignoringRequestMatchers("/api/**"))
                .headers(headers -> {
                    // Essential security headers for APIs
                    headers.contentSecurityPolicy(
                            csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'; sandbox"));
                    // T5.1: HSTS enabled in production via app.security.hsts-enabled
                    if (hstsEnabled) {
                        headers.httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(63072000)
                                .preload(true));
                    }
                    headers.xssProtection(Customizer.withDefaults());
                    headers.referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.valueOf(referrerPolicy)));
                    headers.frameOptions(FrameOptionsConfig::deny);
                    headers.contentTypeOptions(Customizer.withDefaults());
                    headers.addHeaderWriter((request, response) -> {
                        // API-specific security headers
                        response.addHeader("X-Content-Type-Options", "nosniff");
                        response.addHeader("X-API-Version", "v1");
                        response.addHeader("X-Rate-Limit", "enabled");
                        response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
                        response.setHeader("Cross-Origin-Resource-Policy", "same-origin");
                        response.addHeader("Cache-Control", "no-cache, no-store, max-age=0, must-revalidate");
                        response.addHeader("Pragma", "no-cache");
                        response.addHeader("Expires", "0");
                        response.addHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");
                        // Prevent MIME sniffing attacks
                        // Legacy and file-download protections
                        response.setHeader("X-Download-Options", "noopen"); // File-open protection for IE8+
                        response.setHeader("X-Permitted-Cross-Domain-Policies", "none"); // Flash/PDF access restriction
                        // Enhanced Permissions Policy for APIs
                        response.addHeader("Permissions-Policy",
                                "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
                                + "accelerometer=(), autoplay=(), display-capture=(), "
                                + "encrypted-media=(), fullscreen=(), gyroscope=(), "
                                + "magnetometer=(), midi=(), picture-in-picture=(), "
                                + "publickey-credentials-get=(), screen-wake-lock=(), "
                                + "sync-xhr=(), web-share=()");
                    });
                })
                .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // T2.7: JSON error bodies instead of redirects/HTML for API clients
                .exceptionHandling(ex -> ex
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_UNAUTHORIZED);
                    response.setContentType(org.springframework.http.MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write("{\"error\":true,\"status\":401,\"code\":\"unauthorized\"}");
                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setStatus(jakarta.servlet.http.HttpServletResponse.SC_FORBIDDEN);
                    response.setContentType(org.springframework.http.MediaType.APPLICATION_JSON_VALUE);
                    response.getWriter().write("{\"error\":true,\"status\":403,\"code\":\"access_denied\"}");
                }))
                .authorizeHttpRequests(auth -> auth
                // Authenticated auth-session endpoints (checked before public /api/auth/** rule)
                .requestMatchers("/api/auth/logout", "/api/auth/me").authenticated()
                // Public endpoints
                .requestMatchers("/api/auth/**", "/v3/api-docs/**")
                .permitAll()
                // Admin-only endpoints
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .requestMatchers("/api/roles/**", "/api/authorities/**").hasRole("ADMIN")
                // Service endpoints
                .requestMatchers("/api/service/**").hasRole("SERVICE")
                // Push: only privileged roles may broadcast; streaming requires authentication
                .requestMatchers("/api/push/send").hasAnyRole("ADMIN", "SERVICE")
                .requestMatchers("/api/push/stream", "/api/users/**", "/api/last-login/**").authenticated()
                // Default: require authentication
                .anyRequest().authenticated())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // WEB LOGIN FILTER CHAIN
    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http,
            ClientRegistrationRepository clientRegistrationRepository, 
            @Qualifier("OAuth2UserService") OAuth2UserService oAuth2UserService,
            CustomOidcUserService customOidcUserService,
            LogoutSuccessHandler logoutSuccessHandler,
            AuthenticationFailureHandler authenticationFailureHandler,
            AuthenticationSuccessHandler authenticationSuccessHandler,
            // T5.4: Redis-backed session registry for concurrent session control
            SessionRegistry sessionRegistry,
            // 1. Enhanced CSRF filter
            EnhancedCsrfFilter enhancedCsrfFilter,
            // 2. MagicLink authentication filter (LSP-compliant)
            MagicLinkAuthenticationFilter magicLinkAuthenticationFilter,
            // 3. TOTP enforcement filter
            TotpFilter totpFilter)
            throws Exception {

        http
                // Disable CORS for web endpoints - same-origin only
                .cors(cors -> cors.disable())
                .csrf(csrf -> csrf
                .csrfTokenRepository(cookieCsrfTokenRepository())
                .csrfTokenRequestHandler(new CsrfTokenRequestAttributeHandler())
                // Standard CSRF protection
                .ignoringRequestMatchers(
                        "/actuator/**",
                        "/oauth2/**",
                        "/login/oauth2/**",
                        "/api/**", // API endpoints use JWT instead
                        "/error",
                        "/favicon.ico",
                        "/register"))
                .headers(headers -> {
                    // Disable Spring Security's default CSP (Content Security Policy) to prevent nonce generation
                    headers.defaultsDisabled();
                    // T5.1: HSTS enabled in production via app.security.hsts-enabled
                    if (hstsEnabled) {
                        headers.httpStrictTransportSecurity(hsts -> hsts
                                .includeSubDomains(true)
                                .maxAgeInSeconds(63072000)
                                .preload(true));
                    }
                    headers.xssProtection(Customizer.withDefaults());
                    headers.referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.valueOf(referrerPolicy)));
                    headers.frameOptions(FrameOptionsConfig::deny);
                    headers.contentTypeOptions(Customizer.withDefaults());
                    headers.addHeaderWriter((request, response) -> {
                        response.setHeader("Content-Security-Policy",
                                "default-src 'self'; "
                                + "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://accounts.google.com; "
                                + "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://accounts.google.com; "
                                + "font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
                                + "img-src 'self' data: https:; "
                                + "connect-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://accounts.google.com; "
                                + "frame-src https://accounts.google.com; "
                                + "object-src 'none'; "
                                + "frame-ancestors 'none'; "
                                + "base-uri 'self'; "
                                + "form-action 'self'");
                    });
                    headers.addHeaderWriter((request, response) -> {
                        // Add custom security headers
                        response.addHeader("X-Security-Policy", "strict");
                        response.addHeader("X-Rate-Limit", "enabled");
                        // 1. Cross-Origin-Opener-Policy (COOP)
                        // Isolates the site; mitigates Spectre attacks and window-based data leaks.
                        response.addHeader("Cross-Origin-Opener-Policy", "same-origin");

                        // 2. Cross-Origin-Embedder-Policy (COEP)
                        // Only allows loading resources that explicitly opt in (CORP).
                        // Strict rule: require-corp; relaxed rule: credentialless
                        response.addHeader("Cross-Origin-Embedder-Policy", "credentialless");

                        // 3. Cross-Origin-Resource-Policy (CORP)
                        // Prevents other sites from embedding our resources (images, scripts).
                        response.addHeader("Cross-Origin-Resource-Policy", "same-origin");
                        response.addHeader("Cache-Control", "no-cache, no-store, must-revalidate");
                        response.addHeader("Pragma", "no-cache");
                        response.addHeader("Expires", "0");
                        response.addHeader("Permissions-Policy",
                                "geolocation=(), microphone=(), camera=(), payment=(), usb=(), "
                                + "accelerometer=(), autoplay=(), display-capture=(), "
                                + "encrypted-media=(), fullscreen=(), gyroscope=(), "
                                + "magnetometer=(), midi=(), picture-in-picture=(), "
                                + "publickey-credentials-get=(), screen-wake-lock=(), "
                                + "sync-xhr=(), web-share=()");
                    });
                })
                .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/register", "/verify-otp", "/error", 
                        "/swagger-ui/**", "/v3/api-docs/**", "/geo-alert/confirm", "/geo-alert/deny", 
                        "/auth/google-one-tap", "/auth/email-otp/**", "/auth/email-magiclink/**", "/auth/verify")
                .permitAll()
                .requestMatchers("/css/**", "/js/**", "/images/**", "/favicon.ico").permitAll()
                .requestMatchers("/oauth2/**", "/login/oauth2/**").permitAll()
                // Admin monitoring dashboard
                .requestMatchers("/admin/monitoring/**").hasRole("ADMIN")
                // Monitoring endpoints - secure and public
                .requestMatchers("/monitor/health", "/monitor/liveness", "/monitor/readiness").permitAll()
                .requestMatchers("/monitor/health/detailed").hasAnyRole("ADMIN", "SERVICE")
                // T5.2: Prometheus scrapes authenticate with a static Bearer token (MONITORING_TOKEN);
                // interactive access still requires ROLE_ADMIN.
                .requestMatchers("/monitor/metrics", "/monitor/prometheus").access(monitoringAccess())
                .requestMatchers("/monitor/api/**").hasRole("ADMIN")
                // Actuator endpoints with granular security
                .requestMatchers("/actuator/health").permitAll() // Public health check
                .requestMatchers("/actuator/health/liveness").permitAll() // K8s liveness probe
                .requestMatchers("/actuator/health/readiness").permitAll() // K8s readiness probe
                .requestMatchers("/actuator/prometheus").access(monitoringAccess()) // Prometheus metrics (T5.2: Bearer token or ADMIN)
                .requestMatchers("/actuator/info").hasAnyRole("ADMIN", "SERVICE") // Limited info access
                .requestMatchers("/actuator/metrics/**").hasRole("ADMIN") // Metrics for admins only
                .requestMatchers("/actuator/env/**").hasRole("ADMIN") // Environment info
                .requestMatchers("/actuator/beans", "/actuator/conditions", "/actuator/configprops")
                .hasRole("ADMIN")
                .requestMatchers("/actuator/threaddump", "/actuator/heapdump").hasRole("ADMIN")
                .requestMatchers("/actuator/**").hasRole("ADMIN") // All other actuator endpoints
                .requestMatchers("/admin").hasRole("ADMIN")
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .requestMatchers("/service/**").hasRole("SERVICE")
                .anyRequest().authenticated())
                .httpBasic(basic -> basic
                .realmName("Passwordless Multi-Auth Project Monitoring"))
                
                // ========== LSP-COMPLIANT FILTER CHAIN ==========
                // Register our new MagicLink authentication provider with the security chain.
                // The AuthenticationManager will now delegate to it for MagicLinkAuthenticationToken.
                .authenticationProvider(magicLinkAuthenticationProvider)
                
                // 1. CSRF filter
                .addFilterAfter(enhancedCsrfFilter, CsrfFilter.class)
                // 2. Add our custom MagicLink filter. We place it before the TotpFilter, as it's a primary authentication method.
                //    This filter will intercept GET /auth/verify requests.
                .addFilterBefore(magicLinkAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                // 3. TOTP 2FA Filter (Google Authenticator)
                //    Runs after MagicLinkAuthenticationFilter filter.
                //    The TotpFilter will check mfaEnabled and redirect to /totp if needed.
                //    This centralizes 2FA logic for all authentication methods.
                .addFilterAfter(totpFilter, MagicLinkAuthenticationFilter.class)
                // T6.1: Passwordless platform — form login removed; unauthenticated
                // users are redirected to /login (magic link / OAuth2 / email OTP).
                .exceptionHandling(e -> e
                    .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")))
                .logout(logout -> logout
                    .logoutSuccessHandler(logoutSuccessHandler)
                    .invalidateHttpSession(true)
                    .clearAuthentication(true)
                    .deleteCookies("JSESSIONID", "remember-me", "XSRF-TOKEN") // Clear remember-me cookie
                    .permitAll())
                .sessionManagement(session -> {
                    session.sessionFixation().migrateSession(); // Migrate session to prevent session fixation
                    // Concurrent session control - prevent multiple logins
                    session.maximumSessions(1)
                            .maxSessionsPreventsLogin(false) // Allow new login to invalidate old session
                            .sessionRegistry(sessionRegistry)
                            .expiredUrl("/login?expired") // Redirect expired sessions
                            .expiredSessionStrategy(expiredSessionStrategy()); // Custom expired session handling
                    session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
                    session.invalidSessionUrl("/login?expired");
                    session.sessionAuthenticationErrorUrl("/login?error");
                });

        if (clientRegistrationRepository != null) {
            log.info("[SecurityConfig] Configuring OAuth2 login with custom success handler: {}", authenticationSuccessHandler);
            http.oauth2Login(oauth2 -> oauth2
                    .loginPage("/login")
                    .failureUrl("/login?error")
                    .successHandler(authenticationSuccessHandler)
                    .failureHandler(authenticationFailureHandler)
                    .userInfoEndpoint(u -> u
                        .userService(oAuth2UserService)
                        .oidcUserService(customOidcUserService)
                    ));
            log.info("[SecurityConfig] OAuth2 login configuration completed");
        }
        return http.build();
    }

    @Bean
    public CsrfTokenRepository cookieCsrfTokenRepository() {
        CookieCsrfTokenRepository tokenRepository = new CookieCsrfTokenRepository();
        tokenRepository.setCookieCustomizer(new Consumer<ResponseCookie.ResponseCookieBuilder>() {

            @Override
            public void accept(ResponseCookieBuilder t) {
                // Enhanced CSRF cookie security with Double Submit Pattern
                t.sameSite("Strict"); // Prevents CSRF attacks
                t.path("/"); // Cookie available for entire application
                // T5.1: secure flag driven by app.security.secure-cookies (true in production with HTTPS)
                t.secure(secureCookies);
                // CSRF tokens should NOT be httpOnly (JavaScript needs access for validation)
                t.httpOnly(false);
                // Extended expiration for better development experience
                t.maxAge(Duration.ofMinutes(60)); // 60 minutes expiration for development
                // Custom cookie name is set via tokenRepository.setCookieName() method
            }
        });
        // Set custom parameter and header names for additional security
        tokenRepository.setParameterName("_csrf");
        tokenRepository.setHeaderName("X-XSRF-TOKEN");
        // Set custom cookie name for CSRF token
        tokenRepository.setCookieName("XSRF-TOKEN");

        return tokenRepository;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        // Development-friendly CORS configuration for same-origin requests
        CorsConfiguration config = new CorsConfiguration();

        // Allow same-origin requests (localhost development)
        List<String> allowedOrigins = Arrays.asList(allowedOriginsCsv.split(","));
        config.setAllowedOrigins(allowedOrigins);

        // Allow standard HTTP methods
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"));

        // Allow necessary headers for CSRF, authentication, and monitoring
        config.setAllowedHeaders(List.of(
                "Content-Type", "Authorization", "X-Requested-With",
                "X-XSRF-TOKEN", "Accept", "Origin", "Referer",
                "X-Health-Check", "X-Monitor-Source" // Headers for monitoring tools
        ));

        // Enable credentials for same-origin requests (needed for CSRF cookies)
        config.setAllowCredentials(true);

        // Expose CSRF, security, and monitoring headers
        config.setExposedHeaders(List.of(
                "X-XSRF-TOKEN", "X-Health-Status", "X-App-Version"));

        // Cache preflight for development efficiency
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);

        return source;
    }

    @Value("${app.cors.allowed-origins}")
    private String allowedOriginsCsv;

    @Value("${app.cors.health-origins}")
    private String healthOriginsCsv;

    // T5.1: profile-driven production header/cookie hardening
    @Value("${app.security.hsts-enabled:false}")
    private boolean hstsEnabled;

    // T5.2: static Bearer token for Prometheus scrapers (blank = disabled, ADMIN role required)
    @Value("${app.monitoring.token:}")
    private String monitoringToken;

    /**
     * T5.2: Authorization rule for monitoring endpoints. Accepts either the configured
     * static Bearer token (Prometheus scraper) or an authenticated ADMIN user.
     * The platform is passwordless, so HTTP Basic credentials can never work - the
     * token replaces the broken basic-auth setup.
     */
    private AuthorizationManager<RequestAuthorizationContext> monitoringAccess() {
        return (authentication, context) -> {
            String header = context.getRequest().getHeader("Authorization");
            if (monitoringToken != null && !monitoringToken.isBlank()
                    && header != null && header.startsWith("Bearer ")) {
                String presented = header.substring(7);
                if (MessageDigest.isEqual(
                        presented.getBytes(StandardCharsets.UTF_8),
                        monitoringToken.getBytes(StandardCharsets.UTF_8))) {
                    return new org.springframework.security.authorization.AuthorizationDecision(true);
                }
            }
            boolean isAdmin = authentication.get().getAuthorities().stream()
                    .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
            return new org.springframework.security.authorization.AuthorizationDecision(isAdmin);
        };
    }

    @Value("${app.security.secure-cookies:false}")
    private boolean secureCookies;

    @Value("${app.security.referrer-policy:NO_REFERRER}")
    private String referrerPolicy;

 }
