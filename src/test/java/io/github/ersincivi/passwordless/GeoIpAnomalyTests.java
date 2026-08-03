package io.github.ersincivi.passwordless;

// import io.github.ersincivi.passwordless.domain.User;
// import io.github.ersincivi.passwordless.repository.UserRepository;
// import io.github.ersincivi.passwordless.service.EmailService;
// import io.github.ersincivi.passwordless.service.GeoIpService;
// import io.github.ersincivi.passwordless.service.OTPService;
// import io.github.ersincivi.passwordless.service.RateLimiterService;
// import io.github.ersincivi.passwordless.service.RecaptchaService;
// import com.fasterxml.jackson.databind.ObjectMapper;
// import org.junit.jupiter.api.BeforeEach;
// import org.junit.jupiter.api.Test;
// import org.mockito.Mockito;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
// import org.springframework.boot.test.context.SpringBootTest;
// import org.springframework.boot.test.mock.mockito.MockBean;
// import org.springframework.http.MediaType;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.test.web.servlet.MockMvc;

// import java.util.Map;

// import static org.mockito.ArgumentMatchers.*;
// import static org.mockito.Mockito.times;
// import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// import io.github.ersincivi.passwordless.notification.EmailQueueService;
// import io.github.ersincivi.passwordless.notification.EmailQueueMessage;

// @SpringBootTest
// @AutoConfigureMockMvc
class GeoIpAnomalyTests {

    // @Autowired
    // MockMvc mockMvc;
    // @Autowired
    // ObjectMapper objectMapper;
    // @Autowired
    // UserRepository userRepository;
    // @Autowired
    // PasswordEncoder passwordEncoder;

    // @MockBean
    // RecaptchaService recaptchaService;
    // @MockBean
    // RateLimiterService rateLimiterService;
    // @MockBean
    // GeoIpService geoIpService;
    // @MockBean
    // EmailQueueService emailQueueService;
    // @MockBean
    // OTPService otpService;

    String username;

    // @BeforeEach
    // void setup() {
    //     Mockito.when(recaptchaService.verify(anyString(), anyString())).thenReturn(true);
    //     Mockito.when(rateLimiterService.isAllowed(anyString(), anyInt(), any())).thenReturn(true);

    //     username = "geo" + System.currentTimeMillis();
    //     User u = new User();
    //     u.setUsername(username);
    //     u.setEmail(username + "@example.com");
    //     u.setEnabled(true);
    //     u.setLocked(false);
    //     u.setLastLoginIp("1.1.1.1");
    //     userRepository.save(u);

    //     Mockito.when(geoIpService.lookupCountryIso("1.1.1.1")).thenReturn(java.util.Optional.of("AU"));
    //     Mockito.when(geoIpService.lookupCountryIso("8.8.8.8")).thenReturn(java.util.Optional.of("US"));
    //     Mockito.when(otpService.generateOtp("geo:" + username)).thenReturn("111111");
    //     Mockito.when(otpService.verifyOtp(eq("geo:" + username), eq("111111"))).thenReturn(true);
    // }

    // @Test
    // void api_login_geo_anomaly_then_email_otp_then_verify() throws Exception {
    //     // 1) Login from different country IP triggers geo challenge
    //     var body = objectMapper.writeValueAsString(Map.of("username", username, "password", "Secret123"));
    //     mockMvc.perform(post("/api/auth/login")
    //             .contentType(MediaType.APPLICATION_JSON)
    //             .content(body)
    //             .header("X-Recaptcha-Token", "ok")
    //             .with(req -> { req.setRemoteAddr("8.8.8.8"); return req; }))
    //         .andExpect(status().isOk())
    //         .andExpect(jsonPath("$.mfa_required").value(true))
    //         .andExpect(jsonPath("$.geo").value(true));

    //     Mockito.verify(emailQueueService, times(1)).enqueue(argThat((EmailQueueMessage msg) ->
    //         msg.to().equals(username + "@example.com") && msg.body().contains("111111")
    //     ));

    //     // 2) Verify geo OTP and receive JWT
    //     var verify = objectMapper.writeValueAsString(Map.of("username", username, "code", "111111"));
    //     mockMvc.perform(post("/api/auth/geo/verify")
    //             .contentType(MediaType.APPLICATION_JSON)
    //             .content(verify)
    //             .with(req -> { req.setRemoteAddr("8.8.8.8"); return req; }))
    //         .andExpect(status().isOk())
    //         .andExpect(jsonPath("$.token").exists());
    // }
}


