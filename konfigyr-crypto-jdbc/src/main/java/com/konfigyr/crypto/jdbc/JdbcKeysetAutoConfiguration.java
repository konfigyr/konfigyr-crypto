package com.konfigyr.crypto.jdbc;

import com.konfigyr.crypto.CryptoAutoConfiguration;
import com.konfigyr.crypto.KeysetRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.AutoConfigureBefore;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.autoconfigure.sql.init.OnDatabaseInitializationCondition;
import org.springframework.boot.autoconfigure.transaction.TransactionAutoConfiguration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.core.convert.ConversionService;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.support.SQLErrorCodeSQLExceptionTranslator;
import org.springframework.lang.NonNull;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.TransactionDefinition;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.transaction.support.TransactionTemplate;

import javax.sql.DataSource;

/**
 * Spring {@code @AutoConfiguration} class used to configure and initialize a JDBC based
 * implementation of the {@link KeysetRepository}.
 * <p>
 * In order to use this implementation there needs to be at least one {@link DataSource}
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
	KeysetRepository jdbcKeysetRepository(DataSource dataSource, PlatformTransactionManager txManager,
			ObjectProvider<ConversionService> conversionService) {
		final JdbcKeysetRepository repository = new JdbcKeysetRepository(createJdbcOperations(dataSource),
				createTransactionOperations(txManager));

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

	private static TransactionOperations createTransactionOperations(@NonNull PlatformTransactionManager txManager) {
		final TransactionTemplate template = new TransactionTemplate(txManager);
		template.setPropagationBehavior(TransactionDefinition.PROPAGATION_REQUIRES_NEW);
		template.afterPropertiesSet();
		return template;
	}

	static class DatasourceInitializationCondition extends OnDatabaseInitializationCondition {

		DatasourceInitializationCondition() {
			super("Konfigyr JDBC Session", "spring.session.jdbc.initialize-schema");
		}

	}

}
