package io.github.ersincivi.passwordless;

import io.github.ersincivi.passwordless.config.SecurityConfig;
import io.github.ersincivi.passwordless.controller.api.EnhancedAuthorityController;
import io.github.ersincivi.passwordless.controller.api.EnhancedRoleController;
import io.github.ersincivi.passwordless.controller.api.EnhancedUserController;
import io.github.ersincivi.passwordless.controller.api.PushController;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * T6.5: guards the T1 authorization fixes — method security must be enabled
 * and every mapped endpoint on the admin/API controllers must carry an
 * explicit {@link PreAuthorize} rule so no endpoint is ever exposed by an
 * accidentally missing annotation.
 */
class MethodSecurityAnnotationTests {

	private static final List<Class<? extends Annotation>> MAPPING_ANNOTATIONS = List.of(
			GetMapping.class, PostMapping.class, PutMapping.class,
			DeleteMapping.class, PatchMapping.class, RequestMapping.class);

	@Test
	void securityConfigEnablesMethodSecurity() {
		assertThat(SecurityConfig.class.getAnnotation(EnableMethodSecurity.class)).isNotNull();
	}

	@Test
	void roleEndpointsRequireAdminRole() {
		assertAllMappedMethodsProtected(EnhancedRoleController.class, "hasRole('ADMIN')");
	}

	@Test
	void authorityEndpointsRequireAdminRole() {
		assertAllMappedMethodsProtected(EnhancedAuthorityController.class, "hasRole('ADMIN')");
	}

	@Test
	void userEndpointsRequireExplicitAuthorization() {
		assertAllMappedMethodsProtected(EnhancedUserController.class, null);
	}

	@Test
	void userProfileEndpointAllowsSelfAccess() {
		PreAuthorize preAuthorize = mappedMethod(EnhancedUserController.class, "/{username}/profile")
				.getAnnotation(PreAuthorize.class);

		assertThat(preAuthorize).isNotNull();
		assertThat(preAuthorize.value())
				.contains("hasRole('ADMIN')")
				.contains("authentication.name");
	}

	@Test
	void pushSendEndpointRequiresAdminOrServiceRole() {
		PreAuthorize preAuthorize = mappedMethod(PushController.class, "/send")
				.getAnnotation(PreAuthorize.class);

		assertThat(preAuthorize).isNotNull();
		assertThat(preAuthorize.value()).isEqualTo("hasAnyRole('ADMIN','SERVICE')");
	}

	private void assertAllMappedMethodsProtected(Class<?> controller, String expectedExpression) {
		List<Method> mappedMethods = Arrays.stream(controller.getDeclaredMethods())
				.filter(MethodSecurityAnnotationTests::isMapped)
				.toList();

		assertThat(mappedMethods)
				.as("%s must declare at least one mapped endpoint", controller.getSimpleName())
				.isNotEmpty();

		for (Method method : mappedMethods) {
			PreAuthorize preAuthorize = method.getAnnotation(PreAuthorize.class);
			assertThat(preAuthorize)
					.as("%s#%s must carry @PreAuthorize", controller.getSimpleName(), method.getName())
					.isNotNull();
			if (expectedExpression != null) {
				assertThat(preAuthorize.value())
						.as("%s#%s expression", controller.getSimpleName(), method.getName())
						.isEqualTo(expectedExpression);
			}
		}
	}

	private static Method mappedMethod(Class<?> controller, String path) {
		return Arrays.stream(controller.getDeclaredMethods())
				.filter(MethodSecurityAnnotationTests::isMapped)
				.filter(method -> mappingPaths(method).anyMatch(path::equals))
				.findFirst()
				.orElseThrow(() -> new AssertionError(
						"No mapped method for path " + path + " on " + controller.getSimpleName()));
	}

	private static boolean isMapped(Method method) {
		return MAPPING_ANNOTATIONS.stream().anyMatch(method::isAnnotationPresent);
	}

	private static Stream<String> mappingPaths(Method method) {
		return MAPPING_ANNOTATIONS.stream()
				.map(method::getAnnotation)
				.filter(annotation -> annotation != null)
				.flatMap(annotation -> {
					try {
						String[] values = (String[]) annotation.annotationType()
								.getMethod("value")
								.invoke(annotation);
						return Arrays.stream(values);
					} catch (ReflectiveOperationException e) {
						throw new IllegalStateException(e);
					}
				});
	}
}
