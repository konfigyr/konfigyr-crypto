package com.konfigyr.crypto.jdbc;

import com.konfigyr.crypto.KeysetRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.sql.init.DatabaseInitializationMode;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;

import javax.sql.DataSource;
import java.time.Duration;

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
	@DisplayName("should not register JDBC repository when data source is missing")
	void shouldNotApplyConfigurationDueToMissingDataSourceBean() {
		runner.run(ctx -> assertThat(ctx).hasNotFailed()
			.doesNotHaveBean(JdbcKeysetAutoConfiguration.class)
			.doesNotHaveBean(JdbcKeysetRepository.class)
			.doesNotHaveBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class));
	}

	@Test
	@DisplayName("should not register JDBC repository when transaction manager is missing")
	void shouldNotApplyConfigurationDueToMissingTransactionManagerBean() {
		runner.withBean(DataSource.class, () -> dataSource)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.doesNotHaveBean(JdbcKeysetAutoConfiguration.class)
				.doesNotHaveBean(JdbcKeysetRepository.class)
				.doesNotHaveBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class));
	}

	@Test
	@DisplayName("should not register JDBC repository when one is already defined")
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
	@DisplayName("should register JDBC repository and schema initializer")
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
	@DisplayName("should not initialize database schema when disabled")
	void shouldNotRegisterInitializerOnCondition() {
		runner.withBean(DataSource.class, () -> dataSource)
			.withBean(PlatformTransactionManager.class, () -> txManager)
			.withBean(ConversionService.class, GenericConversionService::new)
			.withPropertyValues("konfigyr.crypto.jdbc.initialize-schema=never")
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.hasSingleBean(JdbcKeysetAutoConfiguration.class)
				.hasSingleBean(JdbcKeysetRepository.class)
				.doesNotHaveBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class));
	}

	@Test
	@DisplayName("should not register schema initializer when one is already defined")
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

	@ParameterizedTest
	@CsvSource(delimiter = '|', value = {
		"konfigyr.crypto.jdbc.platform=h2                          | KEYSETS",
		"konfigyr.crypto.jdbc.keysets-table-name=my_schema.KEYSETS | my_schema.KEYSETS",
		"konfigyr.crypto.jdbc.table-name=legacy_schema.KEYSETS     | legacy_schema.KEYSETS"
	})
	@SuppressWarnings("removal")
	@DisplayName("should resolve the keysets table name from configuration properties")
	void shouldResolveKeysetsTableName(String property, String expected) {
		runner.withBean(DataSource.class, () -> dataSource)
			.withBean(PlatformTransactionManager.class, () -> txManager)
			.withBean(ConversionService.class, GenericConversionService::new)
			.withPropertyValues(property, "konfigyr.crypto.jdbc.initialize-schema=never")
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.getBean(JdbcKeysetProperties.class)
				.returns(expected, JdbcKeysetProperties::keysetsTableName)
				.returns(expected, JdbcKeysetProperties::tableName)
				.returns("KEYSET_KEYS", JdbcKeysetProperties::keysTableName));
	}

	@Test
	@SuppressWarnings("removal")
	@DisplayName("should prefer the keysets table name over the deprecated table name property")
	void shouldPreferKeysetsTableNameOverDeprecatedTableName() {
		runner.withBean(DataSource.class, () -> dataSource)
			.withBean(PlatformTransactionManager.class, () -> txManager)
			.withBean(ConversionService.class, GenericConversionService::new)
			.withPropertyValues(
				"konfigyr.crypto.jdbc.table-name=legacy_schema.KEYSETS",
				"konfigyr.crypto.jdbc.keysets-table-name=my_schema.KEYSETS",
				"konfigyr.crypto.jdbc.initialize-schema=never"
			)
			.run(ctx -> assertThat(ctx).hasNotFailed()
				.getBean(JdbcKeysetProperties.class)
				.returns("my_schema.KEYSETS", JdbcKeysetProperties::keysetsTableName)
				.returns("my_schema.KEYSETS", JdbcKeysetProperties::tableName));
	}

	@Test
	@SuppressWarnings("removal")
	@DisplayName("should create properties using the deprecated constructor")
	void shouldCreatePropertiesUsingDeprecatedConstructor() {
		final var properties = new JdbcKeysetProperties("schema.sql", "h2", DatabaseInitializationMode.NEVER,
				"legacy_schema.KEYSETS", "KEYSET_KEYS", Isolation.DEFAULT, Propagation.REQUIRED, Duration.ofSeconds(30));

		assertThat(properties)
			.returns("legacy_schema.KEYSETS", JdbcKeysetProperties::keysetsTableName)
			.returns("legacy_schema.KEYSETS", JdbcKeysetProperties::tableName);
	}

}
