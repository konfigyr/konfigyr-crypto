package com.konfigyr.crypto.jdbc;

import org.springframework.boot.jdbc.DatabaseDriver;
import org.springframework.boot.jdbc.init.DataSourceScriptDatabaseInitializer;
import org.springframework.boot.jdbc.init.PlatformPlaceholderDatabaseDriverResolver;
import org.springframework.boot.sql.init.DatabaseInitializationSettings;
import org.springframework.util.StringUtils;

import javax.sql.DataSource;
import java.util.List;

/**
 * {@link DataSourceScriptDatabaseInitializer} for the Konfigyr Keyseet JDBC database. May
 * be registered as a bean to override autoconfiguration.
 *
 * @author : Vladimir Spasic
 * @since : 28.08.23, Mon
 **/
public class JdbcKeysetDataSourceScriptDatabaseInitializer extends DataSourceScriptDatabaseInitializer {

	public JdbcKeysetDataSourceScriptDatabaseInitializer(DataSource dataSource, JdbcKeysetProperties properties) {
		super(dataSource, settings(dataSource, properties));
	}

	/**
	 * Adapts {@link JdbcKeysetProperties Konfigyr Keyseet JDBC properties} to
	 * {@link DatabaseInitializationSettings} replacing any <code>@@platform@@}</code>
	 * placeholders.
	 * @param dataSource spring data source
	 * @param properties Konfigyr Keyseet JDBC properties
	 * @return a new {@link DatabaseInitializationSettings} instance
	 */
	static DatabaseInitializationSettings settings(DataSource dataSource, JdbcKeysetProperties properties) {
		final DatabaseInitializationSettings settings = new DatabaseInitializationSettings();
		settings.setSchemaLocations(resolveSchemaLocations(dataSource, properties));
		settings.setMode(properties.getInitializeSchema());
		settings.setContinueOnError(true);
		return settings;
	}

	private static List<String> resolveSchemaLocations(DataSource dataSource, JdbcKeysetProperties properties) {
		PlatformPlaceholderDatabaseDriverResolver resolver = new PlatformPlaceholderDatabaseDriverResolver();
		resolver = resolver.withDriverPlatform(DatabaseDriver.MARIADB, "mysql");
		if (StringUtils.hasText(properties.getPlatform())) {
			return resolver.resolveAll(properties.getPlatform(), properties.getSchema());
		}
		return resolver.resolveAll(dataSource, properties.getSchema());
	}

}
