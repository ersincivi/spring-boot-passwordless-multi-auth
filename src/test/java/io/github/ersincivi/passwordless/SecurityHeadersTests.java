package io.github.ersincivi.passwordless;

// import org.junit.jupiter.api.Test;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
// import org.springframework.boot.test.context.SpringBootTest;
// import org.springframework.test.web.servlet.MockMvc;

// import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// @SpringBootTest
// @AutoConfigureMockMvc
class SecurityHeadersTests {

    // @Autowired
    // MockMvc mvc;

    // @Test
    // void headers_present_on_login_page() throws Exception {
    //     mvc.perform(get("/login"))
    //             .andExpect(status().isOk())
    //             .andExpect(header().string("Content-Security-Policy", org.hamcrest.Matchers.containsString("default-src 'self'")))
    //             .andExpect(header().string("X-Frame-Options", org.hamcrest.Matchers.equalToIgnoringCase("DENY")))
    //             .andExpect(header().string("X-Content-Type-Options", org.hamcrest.Matchers.equalToIgnoringCase("nosniff")))
    //             .andExpect(header().string("Referrer-Policy", org.hamcrest.Matchers.equalToIgnoringCase("no-referrer")))
    //             .andExpect(header().string("Permissions-Policy", org.hamcrest.Matchers.containsString("geolocation=()")));
    //     // Note: HSTS is typically only sent over HTTPS; we don't assert it on HTTP.
    // }
}


