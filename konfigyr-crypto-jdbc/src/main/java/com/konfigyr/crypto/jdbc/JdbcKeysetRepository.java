package com.konfigyr.crypto.jdbc;

import com.konfigyr.crypto.*;
import com.konfigyr.crypto.WrappedKeyMaterial;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * A {@link KeysetRepository} implementation that uses Spring's {@link JdbcOperations} to
 * store encrypted private key material, contained within the {@link EncryptedKeyset}, in
 * a relational database.
 * <p>
 * By default, this implementation uses two tables: {@code KEYSETS} for keyset-level metadata
 * and {@code KEYSET_KEYS} for per-key encrypted material with lifecycle timestamps. The table
 * names can be customized via {@link #setTableName(String)} and {@link #setKeysTableName(String)}.
 * <p>
 * Depending on your database, the table definitions can be described as below:
 * <pre class="code">
 * CREATE TABLE KEYSETS (
 *     KEYSET_NAME VARCHAR(120) NOT NULL,
 *     KEYSET_PURPOSE VARCHAR(50) NOT NULL,
 *     KEYSET_FACTORY VARCHAR(255) NOT NULL,
 *     KEYSET_VERSION BIGINT DEFAULT 0 NOT NULL,
 *     KEYSET_PROVIDER VARCHAR(120) NOT NULL,
 *     KEYSET_KEK VARCHAR(255) NOT NULL,
 *     ROTATION_INTERVAL BIGINT,
 *     DESTRUCTION_GRACE_PERIOD BIGINT,
 *     CONSTRAINT KEYSETS_PK PRIMARY KEY (KEYSET_NAME)
 * );
 * CREATE TABLE KEYSET_KEYS (
 *     KEYSET_NAME VARCHAR(120) NOT NULL,
 *     KEY_ID VARCHAR(255) NOT NULL,
 *     KEY_ALGORITHM VARCHAR(255) NOT NULL,
 *     KEY_TYPE VARCHAR(50) NOT NULL,
 *     KEY_STATUS VARCHAR(50) NOT NULL,
 *     KEY_PRIMARY BOOLEAN NOT NULL,
 *     KEY_DATA BLOB,
 *     CREATED_AT BIGINT NOT NULL,
 *     INITIALIZED_AT BIGINT,
 *     EXPIRES_AT BIGINT,
 *     DESTRUCTION_SCHEDULED_AT BIGINT,
 *     DESTROYED_AT BIGINT,
 *     CONSTRAINT KEYSET_KEYS_PK PRIMARY KEY (KEYSET_NAME, KEY_ID),
 *     CONSTRAINT KEYSET_KEYS_FK FOREIGN KEY (KEYSET_NAME) REFERENCES KEYSETS(KEYSET_NAME) ON DELETE CASCADE
 * );
 * </pre>
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
public class JdbcKeysetRepository implements KeysetRepository, InitializingBean {

	/**
	 * The default name of the database table used to store {@link EncryptedKeyset keyset} metadata.
	 */
	public static final String DEFAULT_TABLE_NAME = "KEYSETS";

	/**
	 * The default name of the database table used to store {@link EncryptedKey encrypted keys}.
	 */
	public static final String DEFAULT_KEYS_TABLE_NAME = "KEYSET_KEYS";

	private static final String GET_KEYSET_QUERY = """
			SELECT K.KEYSET_NAME, K.KEYSET_PURPOSE, K.KEYSET_FACTORY, K.KEYSET_PROVIDER, K.KEYSET_KEK, K.ROTATION_INTERVAL, K.DESTRUCTION_GRACE_PERIOD, K.KEYSET_VERSION
			FROM %TABLE_NAME% K
			WHERE K.KEYSET_NAME = ?
			""";

	private static final String GET_KEYS_QUERY = """
			SELECT E.KEY_ID, E.KEY_ALGORITHM, E.KEY_TYPE, E.KEY_STATUS, E.KEY_PRIMARY, E.KEY_DATA,
				E.CREATED_AT, E.INITIALIZED_AT, E.EXPIRES_AT, E.DESTRUCTION_SCHEDULED_AT, E.DESTROYED_AT
			FROM %KEYS_TABLE_NAME% E
			WHERE E.KEYSET_NAME = ?
			ORDER BY E.KEY_ID
			""";

	private static final String KEYSET_EXISTS_QUERY = """
			SELECT 1
			FROM %TABLE_NAME% K
			WHERE K.KEYSET_NAME = ?
			""";

	private static final String CREATE_KEYSET_QUERY = """
			INSERT INTO %TABLE_NAME% (KEYSET_NAME, KEYSET_PURPOSE, KEYSET_FACTORY, KEYSET_PROVIDER, KEYSET_KEK, ROTATION_INTERVAL, DESTRUCTION_GRACE_PERIOD, KEYSET_VERSION)
			VALUES (?, ?, ?, ?, ?, ?, ?, 0)
			""";

	private static final String UPDATE_KEYSET_QUERY = """
			UPDATE %TABLE_NAME%
			SET KEYSET_PURPOSE = ?, KEYSET_FACTORY = ?, KEYSET_PROVIDER = ?, KEYSET_KEK = ?, ROTATION_INTERVAL = ?, DESTRUCTION_GRACE_PERIOD = ?,
				KEYSET_VERSION = KEYSET_VERSION + 1
			WHERE KEYSET_NAME = ? AND KEYSET_VERSION = ?
			""";

	private static final String BUMP_KEYSET_VERSION_QUERY = """
			UPDATE %TABLE_NAME%
			SET KEYSET_VERSION = KEYSET_VERSION + 1
			WHERE KEYSET_NAME = ? AND KEYSET_VERSION = ?
			""";

	private static final String CREATE_KEY_QUERY = """
			INSERT INTO %KEYS_TABLE_NAME% (KEYSET_NAME, KEY_ID, KEY_ALGORITHM, KEY_TYPE, KEY_STATUS, KEY_PRIMARY, KEY_DATA, CREATED_AT, INITIALIZED_AT, EXPIRES_AT, DESTRUCTION_SCHEDULED_AT, DESTROYED_AT)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			""";

	private static final String UPDATE_KEY_QUERY = """
			UPDATE %KEYS_TABLE_NAME%
			SET KEY_ALGORITHM = ?, KEY_TYPE = ?, KEY_STATUS = ?, KEY_PRIMARY = ?, KEY_DATA = ?,
				CREATED_AT = ?, INITIALIZED_AT = ?, EXPIRES_AT = ?, DESTRUCTION_SCHEDULED_AT = ?, DESTROYED_AT = ?
			WHERE KEYSET_NAME = ? AND KEY_ID = ?
			""";

	private static final String DELETE_KEY_QUERY = """
			DELETE FROM %KEYS_TABLE_NAME%
			WHERE KEYSET_NAME = ? AND KEY_ID = ?
			""";

	private static final String DELETE_KEYS_QUERY = """
			DELETE FROM %KEYS_TABLE_NAME%
			WHERE KEYSET_NAME = ?
			""";

	private static final String DELETE_KEYSET_QUERY = """
			DELETE FROM %TABLE_NAME%
			WHERE KEYSET_NAME = ?
			""";

	private static final String UPDATE_KEY_STATUS_QUERY = """
			UPDATE %KEYS_TABLE_NAME%
			SET KEY_STATUS = ?, DESTRUCTION_SCHEDULED_AT = ?, DESTROYED_AT = ?
			WHERE KEYSET_NAME = ? AND KEY_ID = ?
			""";

	private static final String DESTROY_KEY_QUERY = """
			UPDATE %KEYS_TABLE_NAME%
			SET KEY_STATUS = 'DESTROYED', KEY_DATA = NULL, DESTRUCTION_SCHEDULED_AT = NULL, DESTROYED_AT = ?
			WHERE KEYSET_NAME = ? AND KEY_ID = ?
			""";

	private static final String FIND_PENDING_DESTRUCTION_QUERY = """
			SELECT K.KEYSET_NAME, K.KEYSET_PURPOSE, K.KEYSET_FACTORY, K.KEYSET_PROVIDER, K.KEYSET_KEK,
				K.ROTATION_INTERVAL, K.DESTRUCTION_GRACE_PERIOD, K.KEYSET_VERSION,
				E.KEY_ID, E.KEY_ALGORITHM, E.KEY_TYPE, E.KEY_STATUS, E.KEY_PRIMARY, E.KEY_DATA,
				E.CREATED_AT, E.INITIALIZED_AT, E.EXPIRES_AT, E.DESTRUCTION_SCHEDULED_AT, E.DESTROYED_AT
			FROM %TABLE_NAME% K
			INNER JOIN %KEYS_TABLE_NAME% E ON E.KEYSET_NAME = K.KEYSET_NAME
			WHERE E.KEY_STATUS = 'PENDING_DESTRUCTION'
				AND E.DESTRUCTION_SCHEDULED_AT IS NOT NULL
				AND E.DESTRUCTION_SCHEDULED_AT <= ?
			ORDER BY K.KEYSET_NAME, E.KEY_ID
			""";

	private static final String FIND_PENDING_ROTATION_QUERY = """
			SELECT K.KEYSET_NAME, K.KEYSET_PURPOSE, K.KEYSET_FACTORY, K.KEYSET_PROVIDER, K.KEYSET_KEK,
				K.ROTATION_INTERVAL, K.DESTRUCTION_GRACE_PERIOD, K.KEYSET_VERSION
			FROM %TABLE_NAME% K
			INNER JOIN %KEYS_TABLE_NAME% E ON E.KEYSET_NAME = K.KEYSET_NAME
			WHERE E.KEY_PRIMARY = TRUE
				AND E.KEY_STATUS = 'ENABLED'
				AND E.EXPIRES_AT IS NOT NULL
				AND E.EXPIRES_AT <= ?
			ORDER BY K.KEYSET_NAME
			""";

	/* Configurable table names and query overrides */

	private String tableName = DEFAULT_TABLE_NAME;

	private String keysTableName = DEFAULT_KEYS_TABLE_NAME;

	private String getKeysetQuery;

	private String getKeysQuery;

	private String keysetExistsQuery;

	private String createKeysetQuery;

	private String updateKeysetQuery;

	private String createKeyQuery;

	private String updateKeyQuery;

	private String deleteKeyQuery;

	private String deleteKeysQuery;

	private String deleteKeysetQuery;

	private String updateKeyStatusQuery;

	private String destroyKeyQuery;

	private String findPendingDestructionQuery;

	private String findPendingRotationQuery;

	private String bumpKeysetVersionQuery;

	private final JdbcOperations jdbcOperations;

	private final TransactionOperations transactionOperations;

	private final Logger log = LoggerFactory.getLogger(JdbcKeysetRepository.class);

	/**
	 * Creates a new {@link JdbcKeysetRepository} backed by the given JDBC and transaction operations.
	 *
	 * @param jdbcOperations the JDBC operations used to execute database queries, can't be {@literal null}
	 * @param transactionOperations the transaction operations used to wrap writes in a transaction, can't be {@literal null}
	 */
	public JdbcKeysetRepository(JdbcOperations jdbcOperations, TransactionOperations transactionOperations) {
		this.jdbcOperations = jdbcOperations;
		this.transactionOperations = transactionOperations;
	}

	/**
	 * Sets the name of the database table used to store keyset metadata.
	 * Defaults to {@value DEFAULT_TABLE_NAME}.
	 *
	 * @param tableName the table name, can't be {@literal null}
	 */
	public void setTableName(String tableName) {
		this.tableName = tableName;
	}

	/**
	 * Sets the name of the database table used to store encrypted key entries.
	 * Defaults to {@value DEFAULT_KEYS_TABLE_NAME}.
	 *
	 * @param keysTableName the keys table name, can't be {@literal null}
	 */
	public void setKeysTableName(String keysTableName) {
		this.keysTableName = keysTableName;
	}

	/**
	 * Overrides the SQL query used to read a keyset by name.
	 * When {@literal null}, the built-in default query is used.
	 *
	 * @param getKeysetQuery custom SQL query, or {@literal null} to use the default
	 */
	public void setGetKeysetQuery(String getKeysetQuery) {
		this.getKeysetQuery = getKeysetQuery;
	}

	/**
	 * Overrides the SQL query used to read the keys belonging to a keyset.
	 * When {@literal null}, the built-in default query is used.
	 *
	 * @param getKeysQuery custom SQL query, or {@literal null} to use the default
	 */
	public void setGetKeysQuery(String getKeysQuery) {
		this.getKeysQuery = getKeysQuery;
	}

	/**
	 * Overrides the SQL query used to check whether a keyset exists.
	 * When {@literal null}, the built-in default query is used.
	 *
	 * @param keysetExistsQuery custom SQL query, or {@literal null} to use the default
	 */
	public void setKeysetExistsQuery(String keysetExistsQuery) {
		this.keysetExistsQuery = keysetExistsQuery;
	}

	/**
	 * Overrides the SQL statement used to insert a new keyset row.
	 * When {@literal null}, the built-in default statement is used.
	 *
	 * @param createKeysetQuery custom SQL statement, or {@literal null} to use the default
	 */
	public void setCreateKeysetQuery(String createKeysetQuery) {
		this.createKeysetQuery = createKeysetQuery;
	}

	/**
	 * Overrides the SQL statement used to update an existing keyset row.
	 * When {@literal null}, the built-in default statement is used.
	 *
	 * @param updateKeysetQuery custom SQL statement, or {@literal null} to use the default
	 */
	public void setUpdateKeysetQuery(String updateKeysetQuery) {
		this.updateKeysetQuery = updateKeysetQuery;
	}

	/**
	 * Overrides the SQL statement used to insert a new key row.
	 * When {@literal null}, the built-in default statement is used.
	 *
	 * @param createKeyQuery custom SQL statement, or {@literal null} to use the default
	 */
	public void setCreateKeyQuery(String createKeyQuery) {
		this.createKeyQuery = createKeyQuery;
	}

	/**
	 * Overrides the SQL statement used to update an existing key row.
	 * When {@literal null}, the built-in default statement is used.
	 *
	 * @param updateKeyQuery custom SQL statement, or {@literal null} to use the default
	 */
	public void setUpdateKeyQuery(String updateKeyQuery) {
		this.updateKeyQuery = updateKeyQuery;
	}

	/**
	 * Overrides the SQL statement used to delete a single key row.
	 * When {@literal null}, the built-in default statement is used.
	 *
	 * @param deleteKeyQuery custom SQL statement, or {@literal null} to use the default
	 */
	public void setDeleteKeyQuery(String deleteKeyQuery) {
		this.deleteKeyQuery = deleteKeyQuery;
	}

	/**
	 * Overrides the SQL statement used to delete all key rows for a keyset.
	 * When {@literal null}, the built-in default statement is used.
	 *
	 * @param deleteKeysQuery custom SQL statement, or {@literal null} to use the default
	 */
	public void setDeleteKeysQuery(String deleteKeysQuery) {
		this.deleteKeysQuery = deleteKeysQuery;
	}

	/**
	 * Overrides the SQL statement used to delete a keyset row.
	 * When {@literal null}, the built-in default statement is used.
	 *
	 * @param deleteKeysetQuery custom SQL statement, or {@literal null} to use the default
	 */
	public void setDeleteKeysetQuery(String deleteKeysetQuery) {
		this.deleteKeysetQuery = deleteKeysetQuery;
	}

	/**
	 * Overrides the SQL statement used to update the lifecycle status of a key.
	 * When {@literal null}, the built-in default statement is used.
	 *
	 * @param updateKeyStatusQuery custom SQL statement, or {@literal null} to use the default
	 */
	public void setUpdateKeyStatusQuery(String updateKeyStatusQuery) {
		this.updateKeyStatusQuery = updateKeyStatusQuery;
	}

	/**
	 * Overrides the SQL statement used to permanently destroy a key (clear its material and mark it destroyed).
	 * When {@literal null}, the built-in default statement is used.
	 *
	 * @param destroyKeyQuery custom SQL statement, or {@literal null} to use the default
	 */
	public void setDestroyKeyQuery(String destroyKeyQuery) {
		this.destroyKeyQuery = destroyKeyQuery;
	}

	/**
	 * Overrides the SQL query used to find keysets that have keys pending destruction.
	 * When {@literal null}, the built-in default query is used.
	 *
	 * @param findPendingDestructionQuery custom SQL query, or {@literal null} to use the default
	 */
	public void setFindPendingDestructionQuery(String findPendingDestructionQuery) {
		this.findPendingDestructionQuery = findPendingDestructionQuery;
	}

	/**
	 * Overrides the SQL query used to find keysets whose primary key has passed its rotation interval.
	 * When {@literal null}, the built-in default query is used.
	 *
	 * @param findPendingRotationQuery custom SQL query, or {@literal null} to use the default
	 */
	public void setFindPendingRotationQuery(String findPendingRotationQuery) {
		this.findPendingRotationQuery = findPendingRotationQuery;
	}

	/**
	 * Overrides the SQL statement used to increment the keyset version counter.
	 * When {@literal null}, the built-in default statement is used.
	 *
	 * @param bumpKeysetVersionQuery custom SQL statement, or {@literal null} to use the default
	 */
	public void setBumpKeysetVersionQuery(String bumpKeysetVersionQuery) {
		this.bumpKeysetVersionQuery = bumpKeysetVersionQuery;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.hasText(tableName, "Table name for encrypted keysets can not be blank");
		Assert.hasText(keysTableName, "Table name for encrypted keys can not be blank");
		Assert.isTrue(tableName.matches("[A-Za-z][A-Za-z0-9_]*"),
				"Keyset table name must be a valid SQL identifier: " + tableName);
		Assert.isTrue(keysTableName.matches("[A-Za-z][A-Za-z0-9_]*"),
				"Keys table name must be a valid SQL identifier: " + keysTableName);

		getKeysetQuery = sql(getKeysetQuery, GET_KEYSET_QUERY);
		getKeysQuery = sql(getKeysQuery, GET_KEYS_QUERY);
		keysetExistsQuery = sql(keysetExistsQuery, KEYSET_EXISTS_QUERY);
		createKeysetQuery = sql(createKeysetQuery, CREATE_KEYSET_QUERY);
		updateKeysetQuery = sql(updateKeysetQuery, UPDATE_KEYSET_QUERY);
		createKeyQuery = sql(createKeyQuery, CREATE_KEY_QUERY);
		updateKeyQuery = sql(updateKeyQuery, UPDATE_KEY_QUERY);
		deleteKeyQuery = sql(deleteKeyQuery, DELETE_KEY_QUERY);
		deleteKeysQuery = sql(deleteKeysQuery, DELETE_KEYS_QUERY);
		deleteKeysetQuery = sql(deleteKeysetQuery, DELETE_KEYSET_QUERY);
		updateKeyStatusQuery = sql(updateKeyStatusQuery, UPDATE_KEY_STATUS_QUERY);
		destroyKeyQuery = sql(destroyKeyQuery, DESTROY_KEY_QUERY);
		findPendingDestructionQuery = sql(findPendingDestructionQuery, FIND_PENDING_DESTRUCTION_QUERY);
		findPendingRotationQuery = sql(findPendingRotationQuery, FIND_PENDING_ROTATION_QUERY);
		bumpKeysetVersionQuery = sql(bumpKeysetVersionQuery, BUMP_KEYSET_VERSION_QUERY);
	}

	@NonNull
	@Override
	public Optional<EncryptedKeyset> read(@NonNull String name) {
		log.debug("Reading keyset '{}'", name);

		return transactionOperations.execute(status -> {
			final EncryptedKeyset.Builder builder = jdbcOperations.query(
				getKeysetQuery, pss -> pss.setString(1, name), this::extractKeyset);

			if (builder == null) {
				log.debug("Keyset '{}' not found", name);
				return Optional.empty();
			}

			final List<EncryptedKey> keys = jdbcOperations.query(
				getKeysQuery, pss -> pss.setString(1, name), this::extractKeys);

			log.debug("Keyset '{}' found with {} key(s)", name, keys.size());
			return Optional.of(builder.build(keys));
		});
	}

	@NonNull
	@Override
	public EncryptedKeyset write(@NonNull EncryptedKeyset keyset) {
		return transactionOperations.execute(status -> {
			if (exists(keyset.name())) {
				return update(keyset);
			}

			create(keyset);
			return keyset;
		});
	}

	@Override
	public void remove(@NonNull String name) {
		log.debug("Removing keyset '{}'", name);

		transactionOperations.executeWithoutResult(status -> {
			jdbcOperations.update(deleteKeysQuery, pss -> pss.setString(1, name));
			jdbcOperations.update(deleteKeysetQuery, pss -> pss.setString(1, name));
		});
	}

	private void create(EncryptedKeyset keyset) {
		log.debug("Creating keyset '{}' with {} key(s)", keyset.name(), keyset.size());

		jdbcOperations.update(createKeysetQuery, ps -> {
			ps.setString(1, keyset.name());
			ps.setString(2, keyset.purpose());
			ps.setString(3, keyset.factory());
			ps.setString(4, keyset.provider());
			ps.setString(5, keyset.keyEncryptionKey());
			setDuration(ps, 6, keyset.rotationInterval());
			setDuration(ps, 7, keyset.destructionGracePeriod());
		});
		insertKeys(keyset.name(), keyset.keys());
	}

	private EncryptedKeyset update(EncryptedKeyset keyset) {
		log.debug("Updating keyset '{}'", keyset.name());

		final int updated = jdbcOperations.update(updateKeysetQuery, ps -> {
			ps.setString(1, keyset.purpose());
			ps.setString(2, keyset.factory());
			ps.setString(3, keyset.provider());
			ps.setString(4, keyset.keyEncryptionKey());
			setDuration(ps, 5, keyset.rotationInterval());
			setDuration(ps, 6, keyset.destructionGracePeriod());
			ps.setString(7, keyset.name());
			ps.setLong(8, keyset.version());
		});

		if (updated == 0) {
			throw new CryptoException.KeysetConcurrentModificationException(keyset.name());
		}

		updateKeys(keyset.name(), keyset.keys());
		return EncryptedKeyset.builder(keyset).version(keyset.version() + 1).build(keyset.keys());
	}

	/**
	 * Synchronizes the set of {@link EncryptedKey keys} for the given keyset in the database.
	 * Keys absent from {@code newKeys} are deleted; new entries are inserted; changed entries are updated.
	 *
	 * @param keysetName the name of the keyset whose keys are being synchronized, can't be {@literal null}
	 * @param newKeys the desired list of encrypted keys, can't be {@literal null}
	 */
	protected void updateKeys(String keysetName, List<EncryptedKey> newKeys) {
		final List<EncryptedKey> stored = jdbcOperations.query(
			getKeysQuery, pss -> pss.setString(1, keysetName), this::extractKeys);

		final Map<String, EncryptedKey> storedById = new HashMap<>(stored.size());
		for (EncryptedKey key : stored) {
			storedById.put(key.id(), key);
		}

		final List<EncryptedKey> toInsert = new ArrayList<>();
		final List<EncryptedKey> toUpdate = new ArrayList<>();

		for (EncryptedKey key : newKeys) {
			final EncryptedKey existing = storedById.remove(key.id());
			if (existing == null) {
				toInsert.add(key);
			}
			else if (!existing.equals(key)) {
				toUpdate.add(key);
			}
		}

		final List<String> toDelete = storedById.values().stream()
			.filter(key -> key.data() != null)
			.map(EncryptedKey::id)
			.toList();

		if (log.isDebugEnabled()) {
			log.debug("Keyset '{}' key diff: {} inserted, {} updated, {} deleted, {} unchanged",
				keysetName, toInsert.size(), toUpdate.size(), toDelete.size(),
				newKeys.size() - toInsert.size() - toUpdate.size());
		}

		if (!toInsert.isEmpty()) {
			insertKeys(keysetName, toInsert);
		}

		if (!toUpdate.isEmpty()) {
			jdbcOperations.batchUpdate(updateKeyQuery, toUpdate, toUpdate.size(), (ps, key) -> {
				ps.setString(1, key.algorithm());
				ps.setString(2, key.type().name());
				ps.setString(3, key.status().name());
				ps.setBoolean(4, key.primary());
				setBytes(ps, 5, key.data());
				ps.setLong(6, key.createdAt().toEpochMilli());
				setInstant(ps, 7, key.initializedAt());
				setInstant(ps, 8, key.expiresAt());
				setInstant(ps, 9, key.destructionScheduledAt());
				setInstant(ps, 10, key.destroyedAt());
				ps.setString(11, keysetName);
				ps.setString(12, key.id());
			});
		}

		if (!toDelete.isEmpty()) {
			jdbcOperations.batchUpdate(deleteKeyQuery, toDelete, toDelete.size(), (ps, keyId) -> {
				ps.setString(1, keysetName);
				ps.setString(2, keyId);
			});
		}
	}

	/**
	 * Inserts the given list of {@link EncryptedKey keys} for the specified keyset into the database.
	 *
	 * @param keysetName the name of the keyset the keys belong to, can't be {@literal null}
	 * @param keys the keys to insert, can't be {@literal null}
	 */
	protected void insertKeys(String keysetName, List<EncryptedKey> keys) {
		jdbcOperations.batchUpdate(createKeyQuery, keys, keys.size(), (ps, key) -> {
			ps.setString(1, keysetName);
			ps.setString(2, key.id());
			ps.setString(3, key.algorithm());
			ps.setString(4, key.type().name());
			ps.setString(5, key.status().name());
			ps.setBoolean(6, key.primary());
			setBytes(ps, 7, key.data());
			ps.setLong(8, key.createdAt().toEpochMilli());
			setInstant(ps, 9, key.initializedAt());
			setInstant(ps, 10, key.expiresAt());
			setInstant(ps, 11, key.destructionScheduledAt());
			setInstant(ps, 12, key.destroyedAt());
		});
	}

	@Override
	public void updateKeyStatus(@NonNull KeyTransition transition) {
		log.debug("Updating key '{}' in keyset '{}' to status {}",
				transition.keyId(), transition.keysetName(), transition.status());

		transactionOperations.executeWithoutResult(status -> {
			if (transition.status() == KeyStatus.DESTROYED) {
				jdbcOperations.update(destroyKeyQuery, ps -> {
					setInstant(ps, 1, transition.destroyedAt());
					ps.setString(2, transition.keysetName());
					ps.setString(3, transition.keyId());
				});
			}
			else {
				jdbcOperations.update(updateKeyStatusQuery, ps -> {
					ps.setString(1, transition.status().name());
					setInstant(ps, 2, transition.destructionScheduledAt());
					setInstant(ps, 3, transition.destroyedAt());
					ps.setString(4, transition.keysetName());
					ps.setString(5, transition.keyId());
				});
			}
			final int bumped = jdbcOperations.update(bumpKeysetVersionQuery, pss -> {
				pss.setString(1, transition.keysetName());
				pss.setLong(2, transition.keysetVersion());
			});
			if (bumped == 0) {
				throw new CryptoException.KeysetConcurrentModificationException(transition.keysetName());
			}
		});
	}

	@NonNull
	@Override
	public List<EncryptedKeyset> findPendingDestruction() {
		log.debug("Querying for keys pending destruction");

		return transactionOperations.execute(status ->
			jdbcOperations.query(
				findPendingDestructionQuery,
				pss -> pss.setLong(1, Instant.now().toEpochMilli()),
				this::extractPendingDestruction));
	}

	@NonNull
	@Override
	public List<EncryptedKeyset> findPendingRotation() {
		log.debug("Querying for keysets pending rotation");

		return transactionOperations.execute(status ->
			jdbcOperations.query(
				findPendingRotationQuery,
				pss -> pss.setLong(1, Instant.now().toEpochMilli()),
				this::extractPendingRotation));
	}

	private List<EncryptedKeyset> extractPendingRotation(
			@NonNull ResultSet rs) throws SQLException, DataAccessException {
		final List<EncryptedKeyset> result = new ArrayList<>();
		while (rs.next()) {
			result.add(extractKeysetRow(rs).build(List.of()));
		}
		return result;
	}

	private List<EncryptedKeyset> extractPendingDestruction(
			@NonNull ResultSet rs) throws SQLException, DataAccessException {
		final Map<String, EncryptedKeyset.Builder> builders = new LinkedHashMap<>();
		final Map<String, List<EncryptedKey>> keysByName = new LinkedHashMap<>();

		while (rs.next()) {
			final String name = rs.getString("KEYSET_NAME");
			if (!builders.containsKey(name)) {
				builders.put(name, extractKeysetRow(rs));
			}
			keysByName.computeIfAbsent(name, k -> new ArrayList<>()).add(convertKey(rs));
		}

		final List<EncryptedKeyset> result = new ArrayList<>(builders.size());
		for (Map.Entry<String, EncryptedKeyset.Builder> entry : builders.entrySet()) {
			final List<EncryptedKey> keys = keysByName.getOrDefault(entry.getKey(), List.of());
			result.add(entry.getValue().build(keys));
		}
		return result;
	}

	private EncryptedKeyset.Builder extractKeysetRow(@NonNull ResultSet rs) throws SQLException {
		final EncryptedKeyset.Builder builder = EncryptedKeyset.builder()
			.name(rs.getString("KEYSET_NAME"))
			.purpose(KeysetPurpose.valueOf(rs.getString("KEYSET_PURPOSE")))
			.factory(rs.getString("KEYSET_FACTORY"))
			.provider(rs.getString("KEYSET_PROVIDER"))
			.keyEncryptionKey(rs.getString("KEYSET_KEK"))
			.version(rs.getLong("KEYSET_VERSION"));

		final long rotationInterval = rs.getLong("ROTATION_INTERVAL");
		if (!rs.wasNull()) {
			builder.rotationInterval(rotationInterval);
		}

		final long destructionGracePeriod = rs.getLong("DESTRUCTION_GRACE_PERIOD");
		if (!rs.wasNull()) {
			builder.destructionGracePeriod(destructionGracePeriod);
		}

		return builder;
	}

	private boolean exists(@NonNull String name) {
		final Boolean exists = jdbcOperations.query(keysetExistsQuery, pss -> pss.setString(1, name), ResultSet::next);
		return Boolean.TRUE.equals(exists);
	}

	private String sql(@Nullable String query, @NonNull String fallback) {
		return StringUtils.replace(
			StringUtils.replace(query == null ? fallback : query, "%TABLE_NAME%", this.tableName),
			"%KEYS_TABLE_NAME%", this.keysTableName
		);
	}

	private EncryptedKeyset.@Nullable Builder extractKeyset(@NonNull ResultSet rs) throws SQLException, DataAccessException {
		if (!rs.next()) {
			return null;
		}
		return extractKeysetRow(rs);
	}

	private List<EncryptedKey> extractKeys(@NonNull ResultSet rs) throws SQLException, DataAccessException {
		final List<EncryptedKey> keys = new ArrayList<>();
		while (rs.next()) {
			keys.add(convertKey(rs));
		}
		return keys;
	}

	private EncryptedKey convertKey(ResultSet rs) throws SQLException {
		final byte[] data = rs.getBytes("KEY_DATA");

		return EncryptedKey.builder()
			.id(rs.getString("KEY_ID"))
			.algorithm(rs.getString("KEY_ALGORITHM"))
			.type(KeyType.valueOf(rs.getString("KEY_TYPE")))
			.status(KeyStatus.valueOf(rs.getString("KEY_STATUS")))
			.primary(rs.getBoolean("KEY_PRIMARY"))
			.createdAt(Instant.ofEpochMilli(rs.getLong("CREATED_AT")))
			.initializedAt(readInstant(rs, "INITIALIZED_AT"))
			.expiresAt(readInstant(rs, "EXPIRES_AT"))
			.destructionScheduledAt(readInstant(rs, "DESTRUCTION_SCHEDULED_AT"))
			.destroyedAt(readInstant(rs, "DESTROYED_AT"))
			.build(data == null ? null : new ByteArray(data));
	}

	@Nullable
	private static Instant readInstant(ResultSet rs, String column) throws SQLException {
		final long value = rs.getLong(column);
		return rs.wasNull() ? null : Instant.ofEpochMilli(value);
	}

	private static void setDuration(PreparedStatement ps, int index, @Nullable Duration duration) throws SQLException {
		if (duration != null) {
			ps.setLong(index, duration.toMillis());
		}
		else {
			ps.setNull(index, Types.BIGINT);
		}
	}

	private static void setInstant(PreparedStatement ps, int index, @Nullable Instant instant) throws SQLException {
		if (instant != null) {
			ps.setLong(index, instant.toEpochMilli());
		}
		else {
			ps.setNull(index, Types.BIGINT);
		}
	}

	private static void setBytes(PreparedStatement ps, int index, @Nullable WrappedKeyMaterial data) throws SQLException {
		if (data != null) {
			ps.setBytes(index, data.toByteArray());
		} else {
			ps.setNull(index, Types.BINARY);
		}
	}

}
