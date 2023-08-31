package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.KeysetFactory;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class TinkAutoConfigurationTest {

	ApplicationContextRunner runner;

	@BeforeEach
	void setup() {
		runner = new ApplicationContextRunner().withConfiguration(AutoConfigurations.of(TinkAutoConfiguration.class));
	}

	@Test
	void shouldNotApplyConfigurationDueToDeclaredFactoryBean() {
		final var factory = Mockito.mock(KeysetFactory.class);

		runner.withBean(KeysetFactory.class, () -> factory)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.doesNotHaveBean(TinkAutoConfiguration.class)
				.doesNotHaveBean(TinkKeysetFactory.class)
				.getBean(KeysetFactory.class)
				.isEqualTo(factory));
	}

	@Test
	void shouldApplyConfiguration() {
		runner.run(ctx -> assertThat(ctx).hasNotFailed()
			.hasSingleBean(TinkAutoConfiguration.class)
			.hasSingleBean(TinkKeysetFactory.class));
	}

}