package com.konfigyr.crypto.jdbc;

import com.konfigyr.crypto.KeysetRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.transaction.PlatformTransactionManager;

import javax.sql.DataSource;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class JdbcKeysetAutoConfigurationTest {

	@Mock
	DataSource dataSource;

	@Mock
	PlatformTransactionManager txManager;

	ApplicationContextRunner runner;

	@BeforeEach
	void setup() {
		runner = new ApplicationContextRunner()
			.withConfiguration(AutoConfigurations.of(JdbcKeysetAutoConfiguration.class));
	}

	@Test
	void shouldNotApplyConfigurationDueToMissingDataSourceBean() {
		runner.run(ctx -> assertThat(ctx).hasNotFailed()
			.doesNotHaveBean(JdbcKeysetAutoConfiguration.class)
			.doesNotHaveBean(JdbcKeysetRepository.class)
			.doesNotHaveBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class));
	}

	@Test
	void shouldNotApplyConfigurationDueToMissingTransactionManagerBean() {
		runner.withBean(DataSource.class, () -> dataSource)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.doesNotHaveBean(JdbcKeysetAutoConfiguration.class)
				.doesNotHaveBean(JdbcKeysetRepository.class)
				.doesNotHaveBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class));
	}

	@Test
	void shouldNotApplyConfigurationDueToDeclaredRepositoryBean() {
		final var repository = Mockito.mock(KeysetRepository.class);

		runner.withBean(KeysetRepository.class, () -> repository)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.doesNotHaveBean(JdbcKeysetAutoConfiguration.class)
				.doesNotHaveBean(JdbcKeysetRepository.class)
				.doesNotHaveBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class)
				.getBean(KeysetRepository.class)
				.isEqualTo(repository));
	}

	@Test
	void shouldApplyConfiguration() {
		runner.withBean(DataSource.class, () -> dataSource)
			.withBean(PlatformTransactionManager.class, () -> txManager)
			.withBean(ConversionService.class, GenericConversionService::new)
			.withPropertyValues("konfigyr.crypto.jdbc.platform=h2")
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.hasSingleBean(JdbcKeysetAutoConfiguration.class)
				.hasSingleBean(JdbcKeysetRepository.class)
				.hasSingleBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class));
	}

	@Test
	void shouldNotRegisterInitializerOnCondition() {
		runner.withBean(DataSource.class, () -> dataSource)
			.withBean(PlatformTransactionManager.class, () -> txManager)
			.withBean(ConversionService.class, GenericConversionService::new)
			.withPropertyValues("spring.session.jdbc.initialize-schema=never")
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.hasSingleBean(JdbcKeysetAutoConfiguration.class)
				.hasSingleBean(JdbcKeysetRepository.class)
				.doesNotHaveBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class));
	}

	@Test
	void shouldNotRegisterInitializerIfAlreadyDefined() {
		final var initializer = Mockito.mock(JdbcKeysetDataSourceScriptDatabaseInitializer.class);

		runner.withBean(DataSource.class, () -> dataSource)
			.withBean(PlatformTransactionManager.class, () -> txManager)
			.withBean(ConversionService.class, GenericConversionService::new)
			.withBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class, () -> initializer)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.hasSingleBean(JdbcKeysetAutoConfiguration.class)
				.hasSingleBean(JdbcKeysetRepository.class)
				.hasSingleBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class)
				.getBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class)
				.isEqualTo(initializer));
	}

}
