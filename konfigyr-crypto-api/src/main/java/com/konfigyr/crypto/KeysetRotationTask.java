package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.time.Instant;
import java.util.List;

/**
 * Prepares and rotates the keysets managed by the {@link KeysetStore} in two phases:
 * <ol>
 *     <li><em>Prepare</em>: queries {@link KeysetRepository#findPendingPreparation()} and creates the next,
 *     non-primary, key for every keyset whose primary key expires within its rotation lead time.</li>
 *     <li><em>Rotate</em>: queries {@link KeysetRepository#findPendingRotation()} and calls
 *     {@link KeysetStore#rotate(String)} for every keyset whose rotation interval has elapsed. Keysets
 *     that were prepared ahead of the rotation promote their next key to be the primary key.</li>
 * </ol>
 * The prepare phase runs first, so a keyset whose lead time elapsed without being prepared, for instance
 * while the application was down, is still prepared and rotated within the same run. Its next key is then
 * used before third parties could obtain it, which is logged as a warning.
 * <p>
 * Failures for individual keysets are caught and logged so that one failure does not prevent the remaining
 * keysets from being prepared or rotated. A {@link CryptoException.KeysetConcurrentModificationException}
 * is expected when the task runs on multiple nodes and another node already modified the keyset, it is
 * only logged at debug level.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see KeysetTaskAutoConfiguration
 **/
@NullMarked
final class KeysetRotationTask implements Runnable {

	private static final Logger log = LoggerFactory.getLogger(KeysetRotationTask.class);

	private final KeysetStore store;
	private final KeysetRepository repository;

	KeysetRotationTask(KeysetStore store, KeysetRepository repository) {
		this.store = store;
		this.repository = repository;
	}

	@Override
	public void run() {
		prepare();
		rotate();
	}

	private void prepare() {
		final List<EncryptedKeyset> pending;
		try {
			pending = repository.findPendingPreparation();
		} catch (IOException e) {
			log.error("Failed to query for keysets pending preparation", e);
			return;
		}

		if (pending.isEmpty()) {
			return;
		}

		log.debug("Found {} keyset(s) pending preparation", pending.size());

		for (EncryptedKeyset candidate : pending) {
			try {
				prepare(candidate.name());
			} catch (CryptoException.KeysetConcurrentModificationException e) {
				log.debug("Keyset '{}' was modified concurrently while being prepared, skipping it", candidate.name());
			} catch (Exception e) {
				log.error("Failed to prepare keyset '{}'", candidate.name(), e);
			}
		}
	}

	private void prepare(String name) {
		final Keyset keyset = store.read(name);
		final Key primary = keyset.getPrimary();

		// the keyset may have been prepared, or its primary key changed, by another node since it was queried
		if (keyset.getNextKey().isPresent() || !primary.isEnabled()) {
			log.debug("Keyset '{}' no longer needs to be prepared, skipping it", name);
			return;
		}

		final Instant expiresAt = primary.getExpiresAt();

		if (expiresAt != null && !expiresAt.isAfter(Instant.now())) {
			log.warn("Keyset '{}' was not prepared within its rotation lead time, the next key is used before "
				+ "third parties could obtain it", name);
		}

		log.debug("Preparing the next key for keyset '{}'", name);

		store.rotate(keyset, KeyDefinition.builder()
			.algorithm(primary.getAlgorithm())
			.rotationInterval(keyset.getRotationInterval().orElse(null))
			.primary(false)
			.build());
	}

	private void rotate() {
		final List<EncryptedKeyset> pending;
		try {
			pending = repository.findPendingRotation();
		} catch (IOException e) {
			log.error("Failed to query for keysets pending rotation", e);
			return;
		}

		if (pending.isEmpty()) {
			return;
		}

		log.debug("Found {} keyset(s) pending rotation", pending.size());

		for (EncryptedKeyset keyset : pending) {
			try {
				log.debug("Rotating keyset '{}'", keyset.name());
				store.rotate(keyset.name());
			} catch (CryptoException.KeysetConcurrentModificationException e) {
				log.debug("Keyset '{}' was modified concurrently while being rotated, skipping it", keyset.name());
			} catch (Exception e) {
				log.error("Failed to rotate keyset '{}'", keyset.name(), e);
			}
		}
	}

}
