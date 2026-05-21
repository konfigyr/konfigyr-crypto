package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface that is responsible for managing {@link EncryptedKeyset encrypted
 * keysts} at rest.
 *
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 * @see EncryptedKeyset
 * @see KeysetStore
 **/
@NullMarked
public interface KeysetRepository {

	/**
	 * Locate the {@link EncryptedKeyset} by the matching key name from this repository.
	 *
	 * @param name key name, can't be {@literal null}
	 * @return matching {@link Keyset} or an empty {@link Optional}.
	 * @throws IOException if there is an issue while reading the encrypted keyset
	 */
	Optional<EncryptedKeyset> read(String name) throws IOException;

	/**
	 * Writes the data of the {@link EncryptedKeyset} to the repository.
	 *
	 * @param keyset encrypted keyset to be written, can't be {@literal null}
	 * @throws IOException if there is an issue while writing the encrypted keyset
	 */
	void write(EncryptedKeyset keyset) throws IOException;

	/**
	 * Deletes the {@link EncryptedKeyset} by the matching key name from the repository.
	 *
	 * @param name encrypted keyset name to be removed, can't be {@literal null}
	 * @throws IOException if there is an issue while removing the encrypted keyset
	 */
	void remove(String name) throws IOException;

	/**
	 * Applies the given {@link KeyTransition} to a single {@link EncryptedKey} within a stored
	 * {@link EncryptedKeyset}, updating its {@link KeyStatus} and the destruction-related
	 * timestamps carried by the transition.
	 * <p>
	 * When the transition targets {@link KeyStatus#DESTROYED}, implementations
	 * <strong>must</strong> erase the encrypted key material
	 * ({@link EncryptedKey#getData()} becomes {@literal null}).
	 * The row itself is kept for audit purposes.
	 * <p>
	 * The default implementation uses a read-modify-write cycle via {@link #read(String)} and
	 * {@link #write(EncryptedKeyset)}. Implementations that have direct database access should
	 * override this with a targeted SQL {@code UPDATE} for better efficiency.
	 * <p>
	 * If no keyset exists under {@link KeyTransition#getKeysetName()}, this method returns
	 * silently without error.
	 *
	 * @param transition the lifecycle transition to apply, can't be {@literal null}
	 * @throws IOException if there is an issue while updating the key status
	 */
	default void updateKeyStatus(KeyTransition transition) throws IOException {
		final Optional<EncryptedKeyset> existing = read(transition.getKeysetName());
		if (existing.isEmpty()) {
			return;
		}
		final EncryptedKeyset keyset = existing.get();
		final List<EncryptedKey> updatedKeys = new ArrayList<>(keyset.size());
		for (EncryptedKey key : keyset) {
			if (key.getId().equals(transition.getKeyId())) {
				final ByteArray data = transition.getStatus() == KeyStatus.DESTROYED ? null : key.getData();
				updatedKeys.add(EncryptedKey.builder(key)
					.status(transition.getStatus())
					.destructionScheduledAt(transition.getDestructionScheduledAt())
					.destroyedAt(transition.getDestroyedAt())
					.build(data));
			} else {
				updatedKeys.add(key);
			}
		}
		write(EncryptedKeyset.builder(keyset).build(updatedKeys));
	}

	/**
	 * Returns a list of partial {@link EncryptedKeyset} objects where each contains only
	 * the {@link EncryptedKey keys} whose {@link KeyStatus} is
	 * {@link KeyStatus#PENDING_DESTRUCTION} and whose
	 * {@link EncryptedKey#getDestructionScheduledAt() scheduled destruction time} is in the
	 * past (i.e., the grace period has elapsed).
	 * <p>
	 * Each returned {@link EncryptedKeyset} is a <em>partial view</em> — it carries the
	 * keyset metadata but only the eligible pending-destruction keys. Callers typically
	 * iterate the returned keysets and call
	 * {@link com.konfigyr.crypto.KeysetStore#destroy(String, String)} for each key:
	 * <pre>{@code
	 * for (EncryptedKeyset keyset : repository.findPendingDestruction()) {
	 *     for (EncryptedKey key : keyset.getKeys()) {
	 *         store.destroy(keyset.getName(), key.getId());
	 *     }
	 * }
	 * }</pre>
	 * <p>
	 * The default implementation returns an empty list. Repositories that can scan all
	 * stored keysets (e.g. {@link InMemoryKeysetRepository}) or issue an efficient query
	 * (e.g. {@code JdbcKeysetRepository}) should override this method.
	 *
	 * @return list of partial {@link EncryptedKeyset} objects with only their pending-destruction
	 *         keys, never {@literal null}
	 * @throws IOException if there is an issue while querying for pending destruction keys
	 */
	default List<EncryptedKeyset> findPendingDestruction() throws IOException {
		return List.of();
	}

}
