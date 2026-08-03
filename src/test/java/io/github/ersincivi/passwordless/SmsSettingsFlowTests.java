package io.github.ersincivi.passwordless;

// import io.github.ersincivi.passwordless.domain.User;
// import io.github.ersincivi.passwordless.repository.UserRepository;
// import io.github.ersincivi.passwordless.service.MfaService;
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

// import static org.mockito.ArgumentMatchers.anyString;
// import static org.mockito.Mockito.times;
// import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
// import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
// import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// @SpringBootTest
// @AutoConfigureMockMvc
class SmsSettingsFlowTests {

    // @Autowired
    // MockMvc mockMvc;
    // @Autowired
    // UserRepository userRepository;
    // @Autowired
    // PasswordEncoder passwordEncoder;

    // @MockBean
    // MfaService mfaService;

    // User user;

    // @BeforeEach
    // void setup() {
    //     String uname = "sms" + System.currentTimeMillis();
    //     user = new User();
    //     user.setUsername(uname);
    //     user.setEmail(uname + "@example.com");
    //     user.setEnabled(true);
    //     userRepository.save(user);
    //     Mockito.when(mfaService.verifySmsMfa(anyString(), anyString())).thenReturn(true);
    // }

    // @Test
    // void enable_verify_disable_sms_settings() throws Exception {
    //     // enable
    //     mockMvc.perform(post("/settings/mfa-sms/enable").with(csrf())
    //             .param("phone", "+10000000000")
    //             .with(user(user.getUsername()).password("ignored").roles("USER")))
    //         .andExpect(status().is3xxRedirection())
    //         .andExpect(redirectedUrlPattern("/settings?smsVerify"));
    //     Mockito.verify(mfaService, times(1)).startSmsMfa(Mockito.argThat(u -> u.getUsername().equals(user.getUsername())));

    //     // verify
    //     mockMvc.perform(post("/settings/mfa-sms/verify").with(csrf())
    //             .param("code", "123456")
    //             .with(user(user.getUsername()).password("ignored").roles("USER")))
    //         .andExpect(status().is3xxRedirection())
    //         .andExpect(redirectedUrlPattern("/settings?smsEnabled"));

    //     // disable
    //     mockMvc.perform(post("/settings/mfa-sms/disable").with(csrf())
    //             .with(user(user.getUsername()).password("ignored").roles("USER")))
    //         .andExpect(status().is3xxRedirection())
    //         .andExpect(redirectedUrlPattern("/settings?smsDisabled"));
    // }
}


