package com.konfigyr.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.BeanCreationException;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.annotation.Configurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class CryptoAutoConfigurationTest {

	final Configurations configurations = AutoConfigurations.of(CryptoAutoConfiguration.class);

	@Mock
	KeysetFactory factory;

	@Mock
	KeyEncryptionKeyProvider provider;

	ApplicationContextRunner runner;

	@BeforeEach
	void setup() {
		runner = new ApplicationContextRunner().withConfiguration(configurations)
			.withBean(KeysetFactory.class, () -> factory);
	}

	@Test
	@DisplayName("should not register auto-configuration when keyset factory is missing")
	void shouldNotApplyConfigurationDueToMissingKeysetFactory() {
		new ApplicationContextRunner().withConfiguration(configurations).run(ctx -> assertThat(ctx)
			.hasNotFailed()
			.doesNotHaveBean(CryptoAutoConfiguration.class)
			.doesNotHaveBean(RepostoryKeysetStore.class)
			.doesNotHaveBean(InMemoryKeysetRepository.class)
		);
	}

	@Test
	@DisplayName("should not register auto-configuration when keyset store is already defined")
	void shouldNotApplyConfigurationDueToDeclaredStoreBean() {
		final var store = Mockito.mock(KeysetStore.class);

		runner.withBean(KeysetStore.class, () -> store).run(ctx -> assertThat(ctx)
			.hasNotFailed()
			.doesNotHaveBean(CryptoAutoConfiguration.class)
			.doesNotHaveBean(RepostoryKeysetStore.class)
			.doesNotHaveBean(InMemoryKeysetRepository.class)
			.getBean(KeysetStore.class)
			.isEqualTo(store)
		);
	}

	@Test
	@DisplayName("should fail to apply auto-configuration when no KEK providers are present")
	void shouldRequireProvider() {
		runner.run(ctx -> assertThat(ctx)
			.hasFailed()
			.getFailure()
			.isInstanceOf(BeanCreationException.class)
			.hasRootCauseInstanceOf(IllegalArgumentException.class)
			.hasRootCauseMessage("You need to specify at least one key encryption key provider")
		);
	}

	@Test
	@DisplayName("should apply auto-configuration when KEK provider and Keyset factory beans are present")
	void shouldApplyConfiguration() {
		runner.withBean(KeyEncryptionKeyProvider.class, () -> provider).run(ctx -> assertThat(ctx)
			.hasNotFailed()
			.hasSingleBean(CryptoAutoConfiguration.class)
			.hasSingleBean(RepostoryKeysetStore.class)
			.hasSingleBean(InMemoryKeysetRepository.class)
		);
	}

	@Test
	@DisplayName("should not register default in-memory repository when one is already declared")
	void shouldNotRegisterRepositoryWhenAlreadyDeclared() {
		final var repository = Mockito.mock(KeysetRepository.class);

		runner.withBean(KeysetRepository.class, () -> repository)
			.withBean(KeyEncryptionKeyProvider.class, () -> provider)
			.run(ctx -> assertThat(ctx)
				.hasNotFailed()
				.hasSingleBean(CryptoAutoConfiguration.class)
				.hasSingleBean(RepostoryKeysetStore.class)
				.doesNotHaveBean(InMemoryKeysetRepository.class)
				.getBean(KeysetRepository.class)
				.isEqualTo(repository)
			);
	}

}
