package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of the {@link KeysetRepository} that would store the
 * {@link EncryptedKeyset}s in memory.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
@NullMarked
public class InMemoryKeysetRepository implements KeysetRepository {

	private final Map<String, EncryptedKeyset> store = new ConcurrentHashMap<>();

	/**
	 * Creates a new empty in-memory keyset repository.
	 */
	public InMemoryKeysetRepository() {
	}

	@Override
	public Optional<EncryptedKeyset> read(String name) {
		return Optional.ofNullable(store.get(name));
	}

	@Override
	public EncryptedKeyset write(EncryptedKeyset keyset) {
		return store.compute(keyset.name(), (name, existing) -> {
			if (existing != null && existing.version() != keyset.version()) {
				throw new CryptoException.KeysetConcurrentModificationException(name);
			}

			return EncryptedKeyset.builder(keyset)
				.version(existing == null ? 0L : keyset.version() + 1)
				.build(keyset.keys());
		});
	}

	@Override
	public void remove(String name) {
		store.remove(name);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Scans all stored keysets and returns partial {@link EncryptedKeyset} views containing
	 * only the keys in {@link KeyStatus#PENDING_DESTRUCTION} whose scheduled destruction time
	 * is in the past.
	 */
	@Override
	public List<EncryptedKeyset> findPendingDestruction() {
		final Instant now = Instant.now();
		final List<EncryptedKeyset> result = new ArrayList<>();
		for (EncryptedKeyset keyset : store.values()) {
			final List<EncryptedKey> pending = new ArrayList<>();
			for (EncryptedKey key : keyset.keys()) {
				if (key.status() == KeyStatus.PENDING_DESTRUCTION
						&& key.destructionScheduledAt() != null
						&& !key.destructionScheduledAt().isAfter(now)) {
					pending.add(key);
				}
			}
			if (!pending.isEmpty()) {
				result.add(EncryptedKeyset.builder(keyset).build(pending));
			}
		}
		return result;
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * Scans all stored keysets and returns metadata-only {@link EncryptedKeyset} views (empty
	 * key list) for keysets whose primary {@link KeyStatus#ENABLED} key's
	 * {@link EncryptedKey#expiresAt() expiry time} is in the past.
	 */
	@Override
	public List<EncryptedKeyset> findPendingRotation() {
		final Instant now = Instant.now();
		final List<EncryptedKeyset> result = new ArrayList<>();
		for (EncryptedKeyset keyset : store.values()) {
			for (EncryptedKey key : keyset.keys()) {
				if (key.status() == KeyStatus.ENABLED && key.primary()) {
					if (key.expiresAt() != null && !key.expiresAt().isAfter(now)) {
						result.add(EncryptedKeyset.builder(keyset).build(List.of()));
					}
					break;
				}
			}
		}
		return result;
	}

}
