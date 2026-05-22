package com.konfigyr.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.context.annotation.Configurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.scheduling.support.CronTrigger;
import org.springframework.scheduling.support.PeriodicTrigger;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class KeysetTaskAutoConfigurationTest {

	final Configurations configurations = AutoConfigurations.of(KeysetTaskAutoConfiguration.class);

	@Mock
	KeysetStore store;

	@Mock
	KeysetRepository repository;

	ApplicationContextRunner runner;

	@BeforeEach
	void setup() {
		runner = new ApplicationContextRunner()
			.withConfiguration(configurations)
			.withBean(KeysetStore.class, () -> store)
			.withBean(KeysetRepository.class, () -> repository);
	}

	@Test
	@DisplayName("should not register auto-configuration when KeysetStore bean is missing")
	void shouldNotApplyConfigurationDueToMissingKeysetStore() {
		new ApplicationContextRunner()
			.withConfiguration(configurations)
			.withBean(KeysetRepository.class, () -> repository)
			.run(ctx -> assertThat(ctx)
				.hasNotFailed()
				.doesNotHaveBean(KeysetTaskAutoConfiguration.class)
				.doesNotHaveBean(KeysetTaskRegistration.class)
			);
	}

	@Test
	@DisplayName("should not register auto-configuration when KeysetRepository bean is missing")
	void shouldNotApplyConfigurationDueToMissingKeysetRepository() {
		new ApplicationContextRunner()
			.withConfiguration(configurations)
			.withBean(KeysetStore.class, () -> store)
			.run(ctx -> assertThat(ctx)
				.hasNotFailed()
				.doesNotHaveBean(KeysetTaskAutoConfiguration.class)
				.doesNotHaveBean(KeysetTaskRegistration.class)
			);
	}

	@Test
	@DisplayName("should register both task beans with default 1-hour interval when no properties are set")
	void shouldRegisterBothTasksByDefault() {
		runner.run(ctx -> assertThat(ctx)
			.hasNotFailed()
			.hasSingleBean(KeysetTaskAutoConfiguration.class)
			.getBeans(KeysetTaskRegistration.class)
			.containsOnlyKeys("keysetRotationTaskRegistration", "keysetDestructionTaskRegistration")
		);
	}

	@Test
	@DisplayName("should not register rotation task when it is disabled via configuration")
	void shouldNotRegisterRotationTaskWhenDisabled() {
		runner.withPropertyValues("konfigyr.crypto.tasks.keyset-rotation.enabled=false")
			.run(ctx -> assertThat(ctx)
				.hasNotFailed()
				.getBeans(KeysetTaskRegistration.class)
				.containsOnlyKeys("keysetDestructionTaskRegistration")
			);
	}

	@Test
	@DisplayName("should not register destruction task when it is disabled via configuration")
	void shouldNotRegisterDestructionTaskWhenDisabled() {
		runner.withPropertyValues("konfigyr.crypto.tasks.keyset-destruction.enabled=false")
			.run(ctx -> assertThat(ctx)
				.hasNotFailed()
				.getBeans(KeysetTaskRegistration.class)
				.containsOnlyKeys("keysetRotationTaskRegistration")
			);
	}

	@Test
	@DisplayName("should use a periodic trigger when an interval is configured for the rotation task")
	void shouldUsePeriodicTriggerForRotationTask() {
		runner.withPropertyValues("konfigyr.crypto.tasks.keyset-rotation.interval=PT30M")
			.run(ctx -> assertThat(ctx)
				.hasNotFailed()
				.getBean("keysetRotationTaskRegistration", KeysetTaskRegistration.class)
				.extracting("task.trigger")
				.isInstanceOf(PeriodicTrigger.class)
			);
	}

	@Test
	@DisplayName("should use a cron trigger when a cron expression is configured for the destruction task")
	void shouldUseCronTriggerForDestructionTask() {
		runner.withPropertyValues("konfigyr.crypto.tasks.keyset-destruction.cron=0 0 * * * *")
			.run(ctx -> assertThat(ctx)
				.hasNotFailed()
				.getBean("keysetDestructionTaskRegistration", KeysetTaskRegistration.class)
				.extracting("task.trigger")
				.isInstanceOf(CronTrigger.class)
			);
	}

}
