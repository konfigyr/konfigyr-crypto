package com.konfigyr.crypto.jdbc;

import org.jspecify.annotations.Nullable;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.DeprecatedConfigurationProperty;
import org.springframework.boot.context.properties.bind.ConstructorBinding;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.sql.init.DatabaseInitializationMode;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.util.StringUtils;

import java.time.Duration;

/**
 * Configuration properties for JDBC backed {@link com.konfigyr.crypto.KeysetRepository}
 * implementation.
 *
 * @param schema Path to the SQL file used to initialize the database schema;
 *   defaults to the bundled {@code schema-@@platform@@.sql} resource
 * @param platform Platform name used to resolve the {@code @@platform@@} placeholder
 *   in the schema location; when {@literal null} the datasource driver is used to determine
 *   the platform
 * @param initializeSchema Database schema initialization mode; defaults to
 *   {@link DatabaseInitializationMode#EMBEDDED}
 * @param keysetsTableName Name of the database table used to store {@link com.konfigyr.crypto.EncryptedKeyset
 *   keyset} metadata; defaults to {@value JdbcKeysetRepository#DEFAULT_KEYSETS_TABLE_NAME}
 * @param keysTableName Name of the database table used to store {@link com.konfigyr.crypto.EncryptedKey
 *   encrypted keys} with their lifecycle metadata; defaults to {@value JdbcKeysetRepository#DEFAULT_KEYS_TABLE_NAME}
 * @param transactionIsolationLevel Transaction isolation level used by the {@link JdbcKeysetRepository}
 *   when writing to the database; defaults to {@link Isolation#DEFAULT}
 * @param transactionPropagationBehavior Transaction propagation behavior used by the
 *   {@link JdbcKeysetRepository} when writing to the database; defaults to {@link Propagation#REQUIRED}
 * @param transactionTimeout Transaction timeout used by the {@link JdbcKeysetRepository} when
 *   writing to the database; defaults to 30 seconds
 * @param tableName Deprecated name of the database table used to store {@link com.konfigyr.crypto.EncryptedKeyset
 *   keyset} metadata, use {@code keysetsTableName} instead; only used when {@code keysetsTableName} is not set
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see JdbcKeysetRepository
 **/
@SuppressWarnings("removal")
@ConfigurationProperties(prefix = "konfigyr.crypto.jdbc")
public record JdbcKeysetProperties(
		@DefaultValue("classpath:com/konfigyr/crypto/jdbc/schema-@@platform@@.sql") String schema,
		String platform,
		@DefaultValue("embedded") DatabaseInitializationMode initializeSchema,
		String keysetsTableName,
		@DefaultValue("KEYSET_KEYS") String keysTableName,
		@DefaultValue("DEFAULT") Isolation transactionIsolationLevel,
		@DefaultValue("REQUIRED") Propagation transactionPropagationBehavior,
		@DefaultValue("30s") Duration transactionTimeout,
		@Deprecated(since = "1.1.0", forRemoval = true) @Nullable String tableName
) {

	/**
	 * Creates a new {@link JdbcKeysetProperties} instance resolving the keysets table name. The
	 * {@code keysetsTableName} takes precedence over the deprecated {@code tableName}, falling back to
	 * {@value JdbcKeysetRepository#DEFAULT_KEYSETS_TABLE_NAME} when neither of them is set.
	 */
	@ConstructorBinding
	public JdbcKeysetProperties {
		if (!StringUtils.hasText(keysetsTableName)) {
			keysetsTableName = StringUtils.hasText(tableName) ? tableName : JdbcKeysetRepository.DEFAULT_KEYSETS_TABLE_NAME;
		}
	}

	/**
	 * Creates a new {@link JdbcKeysetProperties} instance using the deprecated {@code tableName}
	 * as the name of the keysets table.
	 *
	 * @param schema path to the SQL file used to initialize the database schema
	 * @param platform platform name used to resolve the {@code @@platform@@} placeholder
	 * @param initializeSchema database schema initialization mode
	 * @param tableName name of the database table used to store keyset metadata
	 * @param keysTableName name of the database table used to store encrypted keys
	 * @param transactionIsolationLevel transaction isolation level used when writing to the database
	 * @param transactionPropagationBehavior transaction propagation behavior used when writing to the database
	 * @param transactionTimeout transaction timeout used when writing to the database
	 * @deprecated since 1.1.0, for removal, use the canonical constructor with the {@code keysetsTableName}
	 */
	@Deprecated(since = "1.1.0", forRemoval = true)
	public JdbcKeysetProperties(String schema, String platform, DatabaseInitializationMode initializeSchema,
			String tableName, String keysTableName, Isolation transactionIsolationLevel,
			Propagation transactionPropagationBehavior, Duration transactionTimeout) {
		this(schema, platform, initializeSchema, tableName, keysTableName, transactionIsolationLevel,
				transactionPropagationBehavior, transactionTimeout, null);
	}

	/**
	 * Returns the name of the database table used to store keyset metadata.
	 *
	 * @return the keysets table name, never {@literal null}
	 * @deprecated since 1.1.0, for removal, use {@link #keysetsTableName()} instead
	 */
	@Override
	@Deprecated(since = "1.1.0", forRemoval = true)
	@DeprecatedConfigurationProperty(replacement = "konfigyr.crypto.jdbc.keysets-table-name", since = "1.1.0")
	public String tableName() {
		return keysetsTableName;
	}

}
