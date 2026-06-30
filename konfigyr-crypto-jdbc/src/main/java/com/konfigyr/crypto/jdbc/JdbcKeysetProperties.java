package com.konfigyr.crypto.jdbc;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.boot.sql.init.DatabaseInitializationMode;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;

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
 * @param tableName Name of the database table used to store {@link com.konfigyr.crypto.EncryptedKeyset
 *   keyset} metadata; defaults to {@value JdbcKeysetRepository#DEFAULT_TABLE_NAME}
 * @param keysTableName Name of the database table used to store {@link com.konfigyr.crypto.EncryptedKey
 *   encrypted keys} with their lifecycle metadata; defaults to {@value JdbcKeysetRepository#DEFAULT_KEYS_TABLE_NAME}
 * @param transactionIsolationLevel Transaction isolation level used by the {@link JdbcKeysetRepository}
 *   when writing to the database; defaults to {@link Isolation#DEFAULT}
 * @param transactionPropagationBehavior Transaction propagation behavior used by the
 *   {@link JdbcKeysetRepository} when writing to the database; defaults to {@link Propagation#REQUIRED}
 * @param transactionTimeout Transaction timeout used by the {@link JdbcKeysetRepository} when
 *   writing to the database; defaults to 30 seconds
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see JdbcKeysetRepository
 **/
@ConfigurationProperties(prefix = "konfigyr.crypto.jdbc")
public record JdbcKeysetProperties(
		@DefaultValue("classpath:com/konfigyr/crypto/jdbc/schema-@@platform@@.sql") String schema,
		String platform,
		@DefaultValue("embedded") DatabaseInitializationMode initializeSchema,
		@DefaultValue("KEYSETS") String tableName,
		@DefaultValue("KEYSET_KEYS") String keysTableName,
		@DefaultValue("DEFAULT") Isolation transactionIsolationLevel,
		@DefaultValue("REQUIRED") Propagation transactionPropagationBehavior,
		@DefaultValue("30s") Duration transactionTimeout
) {
}
