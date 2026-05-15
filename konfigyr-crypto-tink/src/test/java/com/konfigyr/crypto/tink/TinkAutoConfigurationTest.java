package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

class TinkAutoConfigurationTest {

	ApplicationContextRunner runner;

	@BeforeEach
	void setup() {
		runner = new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(CryptoAutoConfiguration.class, TinkAutoConfiguration.class))
			.withBean(KeyEncryptionKeyProvider.class, () -> mock(KeyEncryptionKeyProvider.class));
	}

	@Test
	@DisplayName("should not register the Tink autoconfiguration if keyset factory bean is already present")
	void shouldNotApplyConfigurationDueToDeclaredFactoryBean() {
		final var factory = Mockito.mock(TinkKeysetFactory.class);

		runner.withBean("tinkKeysetFactoryOverride", TinkKeysetFactory.class, () -> factory)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.doesNotHaveBean(TinkAutoConfiguration.class)
				.getBean(KeysetFactory.class)
				.isEqualTo(factory));
	}

	@Test
	@DisplayName("should register the Tink keyset factory")
	void shouldApplyConfiguration() {
		runner.run(ctx -> assertThat(ctx).hasNotFailed()
			.hasSingleBean(TinkAutoConfiguration.class)
			.hasSingleBean(TinkKeysetFactory.class)
			.hasSingleBean(AlgorithmRegistry.class)
			.getBean(AlgorithmRegistry.class)
			.satisfies(registry -> assertThat(registry.algorithms())
				.containsExactlyInAnyOrderElementsOf(TinkAlgorithm.DEFAULT_ALGORITHMS)));
	}

}
