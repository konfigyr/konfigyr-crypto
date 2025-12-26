package com.konfigyr.crypto.jdbc;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.sql.init.DatabaseInitializationMode;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Propagation;

import java.time.Duration;

/**
 * Configuration properties for JDBC backed {@link com.konfigyr.crypto.KeysetRepository}
 * implementation.
 *
 * @author : Vladimir Spasic
 * @since : 28.08.23, Mon
 * @see JdbcKeysetRepository
 **/
@Data
@ConfigurationProperties(prefix = "konfigyr.crypto.jdbc")
public class JdbcKeysetProperties {

	/**
	 * Path to the SQL file to use to initialize the database schema.
	 */
	private String schema = "classpath:com/konfigyr/crypto/jdbc/schema-@@platform@@.sql";

	/**
	 * Platform to use in initialization scripts if the <code>@@platform@@</code>
	 * placeholder is used.
	 */
	private String platform;

	/**
	 * Database schema initialization mode.
	 */
	private DatabaseInitializationMode initializeSchema = DatabaseInitializationMode.EMBEDDED;

	/**
	 * Name of the database table used to store {@link com.konfigyr.crypto.EncryptedKeyset
	 * keysets}.
	 */
	private String tableName = JdbcKeysetRepository.DEFAULT_TABLE_NAME;

	/**
	 * Specifies the transaction isolation level that is used by the {@link JdbcKeysetRepository} when writing
	 * to the database. Defaults to {@link Isolation#DEFAULT}.
	 */
	private Isolation transactionIsolationLevel = Isolation.DEFAULT;

	/**
	 * Specifies the transaction propagation behavior that is used by the {@link JdbcKeysetRepository} when
	 * writing to the database. Defaults to {@link Propagation#REQUIRED}.
	 */
	private Propagation transactionPropagationBehavior = Propagation.REQUIRED;

	/**
	 * Specifies the transaction timeout that is used by the {@link JdbcKeysetRepository} when writing
	 * to the database. Defaults to 30 seconds.
	 */
	private Duration transactionTimeout = Duration.ofSeconds(30);

}
