package io.github.ersincivi.passwordless.config;

import io.swagger.v3.oas.models.Components;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.Operation;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.method.HandlerMethod;
import org.springdoc.core.models.GroupedOpenApi;
import org.springdoc.core.customizers.OperationCustomizer;

import java.util.List;

@Configuration
public class OpenApiConfig {

	@Bean
	public OpenAPI api() {
		SecurityScheme bearer = new SecurityScheme()
			.type(SecurityScheme.Type.HTTP)
			.scheme("bearer")
			.bearerFormat("JWT")
			.description("Enter JWT token obtained from MagicLink authentication");
		
		return new OpenAPI()
			.info(new Info()
				.title("Passwordless Multi-Auth API")
				.version("1.0.0")
				.description("""
					Passwordless Multi-Auth Platform API - Passwordless Authentication
					
					This API provides comprehensive endpoints for:
					- MagicLink-based passwordless authentication
					- User management and security operations
					- Role and authority management
					- Push notifications
					- TOTP/MFA verification
					
					## Authentication Flow
					1. Call `POST /api/auth/email-magiclink/send` with user email
					2. User receives MagicLink via email
					3. Call `GET /api/auth/verify?token={token}` to verify
					4. If MFA enabled, call `POST /api/auth/totp/verify`
					5. Use returned JWT in Authorization header: `Bearer {token}`
					
					## Flutter Integration
					For Flutter apps, use the `/api/auth/email-magiclink/send` endpoint
					for mobile authentication. The MagicLink can be handled via
					deep linking in your Flutter app.
					""")
				.contact(new Contact()
					.name("Passwordless Multi-Auth Team")
					.email("api@example.com"))
				.license(new License()
					.name("Private")
					.url("https://github.com/ersincivi/spring-boot-passwordless-multi-auth")))
			.addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
			.components(new Components().addSecuritySchemes("bearerAuth", bearer))
			.servers(List.of(
				new Server().url("http://localhost:8080").description("Local Development"),
				new Server().url("https://api.example.com").description("Production")
			));
	}

	@Bean
	public OperationCustomizer securityByPathCustomizer() {
		return new OperationCustomizer() {
			@Override
			public Operation customize(Operation operation, HandlerMethod handlerMethod) {
				return operation;
			}
		};
	}

	@Bean
	public GroupedOpenApi authOpenApi() {
		return GroupedOpenApi.builder()
			.group("authentication")
			.displayName("Authentication API")
			.pathsToMatch("/api/auth/**")
			.addOperationCustomizer((operation, handlerMethod) -> { 
				operation.setSecurity(java.util.Collections.emptyList()); 
				return operation; 
			})
			.build();
	}

	@Bean
	public GroupedOpenApi userOpenApi() {
		return GroupedOpenApi.builder()
			.group("users")
			.displayName("User Management API")
			.pathsToMatch("/api/users/**")
			.build();
	}

	@Bean
	public GroupedOpenApi roleOpenApi() {
		return GroupedOpenApi.builder()
			.group("roles")
			.displayName("Role Management API")
			.pathsToMatch("/api/roles/**")
			.build();
	}

	@Bean
	public GroupedOpenApi authorityOpenApi() {
		return GroupedOpenApi.builder()
			.group("authorities")
			.displayName("Authority Management API")
			.pathsToMatch("/api/authorities/**")
			.build();
	}

	@Bean
	public GroupedOpenApi lastLoginOpenApi() {
		return GroupedOpenApi.builder()
			.group("last-login")
			.displayName("Last Login Info API")
			.pathsToMatch("/api/last-login/**")
			.build();
	}

	@Bean
	public GroupedOpenApi pushOpenApi() {
		return GroupedOpenApi.builder()
			.group("push")
			.displayName("Push Notification API")
			.pathsToMatch("/api/push/**")
			.build();
	}

	@Bean
	public GroupedOpenApi allApi() {
		return GroupedOpenApi.builder()
			.group("all")
			.displayName("All APIs")
			.pathsToMatch("/api/**")
			.build();
	}
}


