package com.konfigyr.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.annotation.Configurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class CryptoAutoConfigurationTest {

	final Configurations configurations = AutoConfigurations.of(CryptoAutoConfiguration.class);

	@Mock
	KeysetFactory factory;

	ApplicationContextRunner runner;

	@BeforeEach
	void setup() {
		runner = new ApplicationContextRunner().withConfiguration(configurations)
			.withBean(KeysetFactory.class, () -> factory);
	}

	@Test
	void shouldNotApplyConfigurationDueToMissingKeysetFactory() {
		new ApplicationContextRunner().withConfiguration(configurations)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.doesNotHaveBean(CryptoAutoConfiguration.class)
				.doesNotHaveBean(RepostoryKeysetStore.class)
				.doesNotHaveBean(InMemoryKeysetRepository.class));
	}

	@Test
	void shouldNotApplyConfigurationDueToDeclaredStoreBean() {
		final var store = Mockito.mock(KeysetStore.class);

		runner.withBean(KeysetStore.class, () -> store)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.doesNotHaveBean(CryptoAutoConfiguration.class)
				.doesNotHaveBean(RepostoryKeysetStore.class)
				.doesNotHaveBean(InMemoryKeysetRepository.class)
				.getBean(KeysetStore.class)
				.isEqualTo(store));
	}

	@Test
	void shouldApplyConfiguration() {
		runner.run(ctx -> assertThat(ctx).hasNotFailed()
			.hasSingleBean(CryptoAutoConfiguration.class)
			.hasSingleBean(RepostoryKeysetStore.class)
			.hasSingleBean(InMemoryKeysetRepository.class));
	}

	@Test
	void shouldNotRegisterRepositoryWhenAlreadyDeclared() {
		final var repository = Mockito.mock(KeysetRepository.class);

		runner.withBean(KeysetRepository.class, () -> repository)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.hasSingleBean(CryptoAutoConfiguration.class)
				.hasSingleBean(RepostoryKeysetStore.class)
				.doesNotHaveBean(InMemoryKeysetRepository.class)
				.getBean(KeysetRepository.class)
				.isEqualTo(repository));
	}

}