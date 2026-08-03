package io.github.ersincivi.passwordless;

// import io.github.ersincivi.passwordless.domain.User;
// import io.github.ersincivi.passwordless.repository.UserRepository;
// import io.github.ersincivi.passwordless.service.EmailService;
// import org.junit.jupiter.api.Test;
// import org.mockito.ArgumentCaptor;
// import org.springframework.beans.factory.annotation.Autowired;
// import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
// import org.springframework.boot.test.context.SpringBootTest;
// import org.springframework.boot.test.mock.mockito.MockBean;
// import org.springframework.http.MediaType;
// import org.springframework.test.web.servlet.MockMvc;

// import java.util.Optional;

// import static org.assertj.core.api.Assertions.assertThat;
// import static org.mockito.Mockito.verify;
// import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
// import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

// import io.github.ersincivi.passwordless.notification.EmailQueueService;
// import io.github.ersincivi.passwordless.notification.EmailQueueMessage;

// @SpringBootTest
// @AutoConfigureMockMvc
class OtpVerifyTests {

	// @Autowired
	// MockMvc mvc;

	// @Autowired
	// UserRepository users;

	// @MockBean
	// EmailQueueService emailQueueService;

	// @Test
	// void register_then_verifyOtp_activatesUser() throws Exception {
	// 	String unique = String.valueOf(System.currentTimeMillis());
	// 	String email = "otp" + unique + "@example.com";
	// 	String json = "{\"username\":\"otp" + unique + "\",\"email\":\"" + email + "\",\"password\":\"User12345\"}";

	// 	mvc.perform(post("/api/auth/register")
	// 		.contentType(MediaType.APPLICATION_JSON)
	// 		.header("X-Recaptcha-Token", "test")
	// 		.content(json))
	// 		.andExpect(status().isOk());

	// 	ArgumentCaptor<EmailQueueMessage> msgCaptor = ArgumentCaptor.forClass(EmailQueueMessage.class);
	// 	verify(emailQueueService).enqueue(msgCaptor.capture());
	// 	String sentBody = msgCaptor.getValue().body();
	// 	String otp = sentBody.replaceAll("[^0-9]", "").substring(0, 6);

	// 	mvc.perform(post("/api/auth/verify-otp")
	// 		.contentType(MediaType.APPLICATION_JSON)
	// 		.content("{\"email\":\"" + email + "\",\"otp\":\"" + otp + "\"}"))
	// 		.andExpect(status().isOk());

	// 	Optional<User> user = users.findByEmail(email);
	// 	assertThat(user).isPresent();
	// 	assertThat(user.get().isEnabled()).isTrue();
	// }
}


