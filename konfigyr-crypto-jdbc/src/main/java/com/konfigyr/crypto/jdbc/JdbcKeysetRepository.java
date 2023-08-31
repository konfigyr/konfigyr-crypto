package com.konfigyr.crypto.jdbc;

import com.konfigyr.crypto.EncryptedKeyset;
import com.konfigyr.crypto.KeysetRepository;
import com.konfigyr.io.ByteArray;
import lombok.RequiredArgsConstructor;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.transaction.support.TransactionOperations;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * A {@link KeysetRepository} implementation that uses Spring's {@link JdbcOperations} to
 * store encrypted private key material, contained within the {@link EncryptedKeyset}, in
 * a relational database.
 * <p>
 * By default, this implementation uses <code>KEYSETS</code> table to store encrypted
 * keysets. Note that the table name can be customized using the
 * {@link #setTableName(String)} method.
 * <p>
 * Depending on your database, the table definition can be described as below:
 * <pre class="code">
 * CREATE TABLE KEYSETS (
 *     KEYSET_NAME VARCHAR(120) NOT NULL,
 *     KEYSET_ALGORITHM BLOB NOT NULL,
 *     KEYSET_PROVIDER VARCHAR(120) NOT NULL,
 *     KEYSET_KEK VARCHAR(255) NOT NULL,
 *     KEYSET_DATA BLOB NOT NULL,
 *     ROTATION_INTERVAL BIGINT,
 *     NEXT_ROTATION_TIME BIGINT,
 *     CONSTRAINT KEYSETS_PK PRIMARY KEY (KEYSET_NAME)
 * );
 * </pre>
 *
 * @author : Vladimir Spasic
 * @since : 28.08.23, Mon
 **/
@Slf4j
@Setter
@RequiredArgsConstructor
public class JdbcKeysetRepository implements KeysetRepository, InitializingBean {

	/**
	 * The default name of database table to store {@link EncryptedKeyset keysets}.
	 */
	public static final String DEFAULT_TABLE_NAME = "KEYSETS";

	private static final String GET_KEYSET_QUERY = """
			SELECT K.KEYSET_NAME, K.KEYSET_ALGORITHM, K.KEYSET_PROVIDER, K.KEYSET_KEK, K.KEYSET_DATA, K.ROTATION_INTERVAL, K.NEXT_ROTATION_TIME
			FROM %TABLE_NAME% K
			WHERE K.KEYSET_NAME = ?
			""";

	private static final String KEYSET_EXISTS_QUERY = """
			SELECT 1
			FROM %TABLE_NAME% K
			WHERE K.KEYSET_NAME = ?
			""";

	private static final String LIST_KEYSETS_FOR_ROTATION_QUERY = """
			SELECT K.KEYSET_NAME, K.KEYSET_ALGORITHM, K.KEYSET_KEK K.KEYSET_DATA, K.ROTATION_INTERVAL, K.NEXT_ROTATION_TIME
			FROM %TABLE_NAME% K
			WHERE K.NEXT_ROTATION_TIME < ?
			""";

	private static final String CREATE_KEYSET_QUERY = """
			INSERT INTO %TABLE_NAME% (KEYSET_NAME, KEYSET_ALGORITHM, KEYSET_PROVIDER, KEYSET_KEK, KEYSET_DATA, ROTATION_INTERVAL, NEXT_ROTATION_TIME)
			VALUES (?, ?, ?, ?, ?, ?, ?)
			""";

	private static final String UPDATE_KEYSET_QUERY = """
			UPDATE %TABLE_NAME%
			SET KEYSET_PROVIDER = ?, KEYSET_KEK = ?, KEYSET_DATA = ?, ROTATION_INTERVAL = ?, NEXT_ROTATION_TIME = ?
			WHERE KEYSET_NAME = ?
			""";

	private static final String DELETE_KEYSET_QUERY = """
			DELETE FROM %TABLE_NAME%
			WHERE KEYSET_NAME = ?
			""";

	/* Queries to be used by the repository */

	private String tableName = DEFAULT_TABLE_NAME;

	private String listKeysetsQuery;

	private String keysetExistsQuery;

	private String listKeysetsForRotationQuery;

	private String createKeysetQuery;

	private String updateKeysetQuery;

	private String deleteKeysetQuery;

	private LobHandler lobHandler = new DefaultLobHandler();

	private final JdbcOperations jdbcOperations;

	private final TransactionOperations transactionOperations;

	@Override
	public void afterPropertiesSet() {
		Assert.hasText(tableName, "Table name for encrypted keysets can not be blank");
		Assert.notNull(lobHandler, "Lob handler can not be null");

		listKeysetsQuery = sql(listKeysetsQuery, GET_KEYSET_QUERY);
		keysetExistsQuery = sql(keysetExistsQuery, KEYSET_EXISTS_QUERY);
		listKeysetsForRotationQuery = sql(listKeysetsForRotationQuery, LIST_KEYSETS_FOR_ROTATION_QUERY);
		createKeysetQuery = sql(createKeysetQuery, CREATE_KEYSET_QUERY);
		updateKeysetQuery = sql(updateKeysetQuery, UPDATE_KEYSET_QUERY);
		deleteKeysetQuery = sql(deleteKeysetQuery, DELETE_KEYSET_QUERY);
	}

	@NonNull
	@Override
	public Optional<EncryptedKeyset> read(@NonNull String name) {
		final List<EncryptedKeyset> keysets = transactionOperations
			.execute(status -> jdbcOperations.query(listKeysetsQuery, pss -> pss.setString(1, name), this::extract));

		if (CollectionUtils.isEmpty(keysets)) {
			return Optional.empty();
		}

		return Optional.of(keysets.get(0));
	}

	@NonNull
	@Override
	public void write(@NonNull EncryptedKeyset keyset) {
		transactionOperations.executeWithoutResult(status -> {
			if (exists(keyset.getName())) {
				update(keyset);
			}
			else {
				create(keyset);
			}
		});
	}

	@NonNull
	@Override
	public void remove(@NonNull String name) {
		transactionOperations.executeWithoutResult(status -> jdbcOperations.update(deleteKeysetQuery, pss -> {
			pss.setString(1, name);
		}));
	}

	private void create(EncryptedKeyset keyset) {
		jdbcOperations.update(createKeysetQuery, ps -> {
			ps.setString(1, keyset.getName());
			ps.setString(2, keyset.getAlgorithm());
			ps.setString(3, keyset.getProvider());
			ps.setString(4, keyset.getKeyEncryptionKey());

			try (final var creator = lobHandler.getLobCreator()) {
				creator.setBlobAsBytes(ps, 5, keyset.getData().array());
			}

			ps.setLong(6, keyset.getRotationInterval().toMillis());
			ps.setLong(7, keyset.getNextRotationTime().toEpochMilli());
		});
	}

	private void update(EncryptedKeyset keyset) {
		jdbcOperations.update(updateKeysetQuery, ps -> {
			ps.setString(1, keyset.getProvider());
			ps.setString(2, keyset.getKeyEncryptionKey());

			try (final var creator = lobHandler.getLobCreator()) {
				creator.setBlobAsBytes(ps, 3, keyset.getData().array());
			}

			ps.setLong(4, keyset.getRotationInterval().toMillis());
			ps.setLong(5, keyset.getNextRotationTime().toEpochMilli());
			ps.setString(6, keyset.getName());
		});
	}

	private boolean exists(@NonNull String name) {
		final Boolean exists = jdbcOperations.query(keysetExistsQuery, pss -> pss.setString(1, name), ResultSet::next);

		return Boolean.TRUE.equals(exists);
	}

	private String sql(@Nullable String query, @NonNull String fallback) {
		return StringUtils.replace(query == null ? fallback : query, "%TABLE_NAME%", this.tableName);
	}

	private List<EncryptedKeyset> extract(@NonNull ResultSet rs) throws SQLException, DataAccessException {
		final List<EncryptedKeyset> keysets = new ArrayList<>();

		while (rs.next()) {
			keysets.add(convert(rs));
		}

		return keysets;
	}

	private EncryptedKeyset convert(ResultSet rs) throws SQLException {
		final byte[] data = lobHandler.getBlobAsBytes(rs, "KEYSET_DATA");

		return EncryptedKeyset.builder()
			.name(rs.getString("KEYSET_NAME"))
			.algorithm(rs.getString("KEYSET_ALGORITHM"))
			.provider(rs.getString("KEYSET_PROVIDER"))
			.keyEncryptionKey(rs.getString("KEYSET_KEK"))
			.rotationInterval(rs.getLong("ROTATION_INTERVAL"))
			.nextRotationTime(rs.getLong("NEXT_ROTATION_TIME"))
			.build(new ByteArray(data));
	}

}
