package com.konfigyr.crypto.jdbc;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.sql.init.DatabaseInitializationMode;

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
	 * <p>
	 * The value is set to {@literal default} and should only be changed to
	 * {@literal oracle}.
	 */
	private String platform = "default";

	/**
	 * Database schema initialization mode.
	 */
	private DatabaseInitializationMode initializeSchema = DatabaseInitializationMode.EMBEDDED;

	/**
	 * Name of the database table used to store {@link com.konfigyr.crypto.EncryptedKeyset
	 * keysets}.
	 */
	private String tableName = JdbcKeysetRepository.DEFAULT_TABLE_NAME;

}
