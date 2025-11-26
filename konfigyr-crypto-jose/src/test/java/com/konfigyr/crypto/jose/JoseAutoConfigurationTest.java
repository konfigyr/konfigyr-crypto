package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.KeysetFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class JoseAutoConfigurationTest {

	ApplicationContextRunner runner;

	@BeforeEach
	void setup() {
		runner = new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(JoseAutoConfiguration.class));
	}

	@Test
	@DisplayName("should not register the JOSE keyset factory if one is already present")
	void shouldNotApplyConfigurationDueToDeclaredFactoryBean() {
		final var factory = Mockito.mock(JoseKeysetFactory.class);

		runner.withBean("joseKeysetFactoryOverride", JoseKeysetFactory.class, () -> factory)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.doesNotHaveBean(JoseAutoConfiguration.class)
				.getBean(KeysetFactory.class)
				.isEqualTo(factory));
	}

	@Test
	@DisplayName("should register the JOSE keyset factory")
	void shouldApplyConfiguration() {
		runner.run(ctx -> assertThat(ctx).hasNotFailed()
			.hasSingleBean(JoseAutoConfiguration.class)
			.hasSingleBean(JoseKeysetFactory.class));
	}

}
