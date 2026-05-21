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
 * @author : Vladimir Spasic
 * @since : 27.08.23, Sun
 **/
@NullMarked
public class InMemoryKeysetRepository implements KeysetRepository {

	private final Map<String, EncryptedKeyset> store = new ConcurrentHashMap<>();

	@Override
	public Optional<EncryptedKeyset> read(String name) {
		return Optional.ofNullable(store.get(name));
	}

	@Override
	public void write(EncryptedKeyset keyset) {
		store.put(keyset.getName(), keyset);
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
			for (EncryptedKey key : keyset.getKeys()) {
				if (key.getStatus() == KeyStatus.PENDING_DESTRUCTION
						&& key.getDestructionScheduledAt() != null
						&& !key.getDestructionScheduledAt().isAfter(now)) {
					pending.add(key);
				}
			}
			if (!pending.isEmpty()) {
				result.add(EncryptedKeyset.builder(keyset).build(pending));
			}
		}
		return result;
	}

}
