package io.github.ersincivi.passwordless;

// import io.github.ersincivi.passwordless.domain.User;
// import io.github.ersincivi.passwordless.repository.UserRepository;
// import io.github.ersincivi.passwordless.service.TotpService;
// import com.fasterxml.jackson.databind.ObjectMapper;
// import com.warrenstrange.googleauth.GoogleAuthenticator;
// import org.junit.jupiter.api.BeforeEach;
// import org.junit.jupiter.api.Test;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
// import org.springframework.boot.test.context.SpringBootTest;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.test.context.ActiveProfiles;
// import org.springframework.test.context.TestPropertySource;
// import org.springframework.test.web.servlet.MockMvc;
// import org.springframework.test.web.servlet.MvcResult;

// import jakarta.servlet.http.Cookie;
// import java.util.Map;

// import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
// import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
// import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

// @SpringBootTest
// @AutoConfigureMockMvc
// @ActiveProfiles("dev")
// @TestPropertySource(properties = {
//     "app.recaptcha.enabled=false"
// })
public class TotpFlowTests {

    // @Autowired
    // MockMvc mvc;

    // @Autowired
    // UserRepository users;

    // @Autowired
    // PasswordEncoder passwordEncoder;

    // @Autowired
    // ObjectMapper objectMapper;

    // @Autowired
    // TotpService totpService;

    // private String username;
    // private String password;
    // private String secret;

    // @BeforeEach
    // void setup() {
    //     username = "totpuser" + System.currentTimeMillis();
    //     password = "P@ssw0rd";
    //     secret = "JBSWY3DPEHPK3PXP"; // Base32

    //     User u = new User();
    //     u.setUsername(username);
    //     u.setEmail(username + "@example.com");
    //     u.setEnabled(true);
    //     u.setMfaEnabled(true);
    //     u.setMfaSecret(secret);
    //     users.save(u);
    // }

    // @Test
    // void api_login_requires_totp_then_verify_returns_jwt() throws Exception {
    //     String loginJson = objectMapper.writeValueAsString(Map.of(
    //         "username", username,
    //         "password", password
    //     ));

    //     mvc.perform(post("/api/auth/login").contentType("application/json").content(loginJson))
    //         .andExpect(status().isOk())
    //         .andExpect(jsonPath("$.mfa_required").value(true))
    //         .andExpect(jsonPath("$.totp").value(true));

    //     int code = new GoogleAuthenticator().getTotpPassword(secret);
    //     String verifyJson = objectMapper.writeValueAsString(Map.of(
    //         "username", username,
    //         "code", String.valueOf(code)
    //     ));

    //     mvc.perform(post("/api/auth/totp/verify").contentType("application/json").content(verifyJson))
    //         .andExpect(status().isOk())
    //         .andExpect(jsonPath("$.token").isNotEmpty());
    // }

    // @Test
    // void web_login_redirects_to_totp_then_verifies_and_allows_home() throws Exception {
    //     MvcResult loginResult = mvc.perform(post("/login").with(csrf())
    //             .param("username", username)
    //             .param("password", password))
    //         .andExpect(status().is3xxRedirection())
    //         .andExpect(redirectedUrl("/"))
    //         .andReturn();

    //     Cookie sessionCookie = loginResult.getResponse().getCookie("SESSION");

    //     mvc.perform(get("/").cookie(sessionCookie))
    //         .andExpect(status().is3xxRedirection())
    //         .andExpect(redirectedUrl("/totp"));

    //     int code = new GoogleAuthenticator().getTotpPassword(secret);

    //     mvc.perform(post("/totp").with(csrf())
    //             .cookie(sessionCookie)
    //             .param("code", String.valueOf(code)))
    //         .andExpect(status().is3xxRedirection())
    //         .andExpect(redirectedUrl("/"));

    //     mvc.perform(get("/").cookie(sessionCookie))
    //         .andExpect(status().isOk());
    // }
}


