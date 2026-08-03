package io.github.ersincivi.passwordless.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

@Configuration
public class RestClientConfig {

    // GitHub API'sine özel bir RestClient Bean
    @Bean
    public RestClient gitHubRestClient(RestClient.Builder builder) {
        return builder
                // 1. Temel URI'yi (Base URL) ayarla
                .baseUrl("https://api.github.com/")
                // 2. Accept JSON by default
                .defaultHeader("Accept", MediaType.APPLICATION_JSON_VALUE)
                // 3. Customize timeout settings (optional)
                .requestFactory(new org.springframework.http.client.SimpleClientHttpRequestFactory() {{
                    setConnectTimeout(5000); // Connect timeout: 5 seconds
                    setReadTimeout(10000);   // Read timeout: 10 seconds
                }})
                .build();
    }

    // Additional RestClient beans can be defined for other services. Example:
    // @Bean 
    // public RestClient thirdPartyServiceRestClient(RestClient.Builder builder) { ... }
}
