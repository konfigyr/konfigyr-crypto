package com.konfigyr.crypto.jdbc;

import com.konfigyr.crypto.CryptoAutoConfiguration;
import com.konfigyr.crypto.KeysetRepository;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.sql.autoconfigure.init.OnDatabaseInitializationCondition;
import org.springframework.boot.transaction.autoconfigure.TransactionAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.SQLErrorCodeSQLExceptionTranslator;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;

/**
 * Spring {@code @AutoConfiguration} class used to configure and initialize a JDBC-based
 * implementation of the {@link KeysetRepository}.
 * <p>
 * To use this implementation, there needs to be at least one {@link DataSource}
 * and {@link PlatformTransactionManager} Spring Bean.
 *
 * @author : Vladimir Spasic
 * @since : 28.08.23, Mon
 **/
@RequiredArgsConstructor
@AutoConfiguration
@AutoConfigureAfter({ DataSourceAutoConfiguration.class, TransactionAutoConfiguration.class })
@AutoConfigureBefore(CryptoAutoConfiguration.class)
@EnableConfigurationProperties(JdbcKeysetProperties.class)
@ConditionalOnBean({ DataSource.class, PlatformTransactionManager.class })
@ConditionalOnMissingBean(KeysetRepository.class)
public class JdbcKeysetAutoConfiguration {

	private final JdbcKeysetProperties properties;

	@Bean
	KeysetRepository jdbcKeysetRepository(DataSource dataSource, PlatformTransactionManager txManager) {
		final JdbcKeysetRepository repository = new JdbcKeysetRepository(createJdbcOperations(dataSource),
				createTransactionOperations(txManager, properties));

		repository.setTableName(properties.getTableName());

		return repository;
	}

	@Bean
	@Conditional(DatasourceInitializationCondition.class)
	@ConditionalOnMissingBean(JdbcKeysetDataSourceScriptDatabaseInitializer.class)
	JdbcKeysetDataSourceScriptDatabaseInitializer jdbcKeysetDataSourceScriptDatabaseInitializer(
			BeanFactory beanFactory) {
		return new JdbcKeysetDataSourceScriptDatabaseInitializer(beanFactory.getBean(DataSource.class), properties);
	}

	private static JdbcOperations createJdbcOperations(@NonNull DataSource dataSource) {
		final JdbcTemplate template = new JdbcTemplate(dataSource);
		template.setExceptionTranslator(new SQLErrorCodeSQLExceptionTranslator());
		template.afterPropertiesSet();
		return template;
	}

	private static TransactionOperations createTransactionOperations(
		@NonNull PlatformTransactionManager txManager,
		@NonNull JdbcKeysetProperties properties
	) {
		final TransactionTemplate template = new TransactionTemplate(txManager);
		template.setPropagationBehavior(properties.getTransactionPropagationBehavior().value());
		template.setIsolationLevel(properties.getTransactionIsolationLevel().value());
		template.setTimeout((int) properties.getTransactionTimeout().toSeconds());
		template.setName("jdbc-keyset-repository-transaction-operations");
		template.setReadOnly(false);
		template.afterPropertiesSet();
		return template;
	}

	static class DatasourceInitializationCondition extends OnDatabaseInitializationCondition {

		DatasourceInitializationCondition() {
			super("Konfigyr JDBC Session", "konfigyr.crypto.jdbc.initialize-schema");
		}

	}

}
