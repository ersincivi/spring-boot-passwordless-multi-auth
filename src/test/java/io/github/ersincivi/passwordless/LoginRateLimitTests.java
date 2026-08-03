package io.github.ersincivi.passwordless;

// import org.junit.jupiter.api.Test;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
// import org.springframework.boot.test.context.SpringBootTest;
// import org.springframework.http.MediaType;
// import org.springframework.test.web.servlet.MockMvc;

// import static org.hamcrest.Matchers.containsString;
// import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
// import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;

// @SpringBootTest(properties = {
//         "app.recaptcha.enabled=false"
// })
// @AutoConfigureMockMvc
class LoginRateLimitTests {

    // @Autowired
    // MockMvc mvc;

    // @Test
    // void api_login_rate_limit_blocks_after_threshold() throws Exception {
    //     String uniqueUser = "rate_" + System.currentTimeMillis();

    //     // Perform attempts up to the threshold (default 5) with bad credentials
    //     for (int i = 0; i < 5; i++) {
    //         mvc.perform(post("/api/auth/login")
    //                 .contentType(MediaType.APPLICATION_JSON)
    //                 .header("X-Recaptcha-Token", "test")
    //                 .content("{\"username\":\"" + uniqueUser + "\",\"password\":\"bad\"}")
    //                 .with(csrf())) // <-- Adds the CSRF token to every request
    //                 .andExpect(status().is4xxClientError());
    //     }

    //     // Next attempt should trigger rate limit error from RateLimiterService
    //     mvc.perform(post("/api/auth/login")
    //             .contentType(MediaType.APPLICATION_JSON)
    //             .header("X-Recaptcha-Token", "test")
    //             .content("{\"username\":\"" + uniqueUser + "\",\"password\":\"bad\"}")
    //             .with(csrf())) // <-- Adds the CSRF token to the final request as well
    //             .andExpect(status().isTooManyRequests());
    // }
}
