package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

/**
 * Queries {@link KeysetRepository#findPendingDestruction()} and calls
 * {@link KeysetStore#destroy(String, String)} for every key whose grace period has
 * elapsed. Failures for individual keys are caught and logged so that one failure
 * does not prevent the remaining keys from being destroyed.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see KeysetTaskAutoConfiguration
 **/
@NullMarked
final class KeysetDestructionTask implements Runnable {

	private static final Logger log = LoggerFactory.getLogger(KeysetDestructionTask.class);

	private final KeysetStore store;
	private final KeysetRepository repository;

	KeysetDestructionTask(KeysetStore store, KeysetRepository repository) {
		this.store = store;
		this.repository = repository;
	}

	@Override
	public void run() {
		final List<EncryptedKeyset> pending;
		try {
			pending = repository.findPendingDestruction();
		} catch (IOException e) {
			log.error("Failed to query for keys pending destruction", e);
			return;
		}

		if (pending.isEmpty()) {
			return;
		}

		log.debug("Found {} keyset(s) with keys pending destruction", pending.size());

		for (EncryptedKeyset keyset : pending) {
			for (EncryptedKey key : keyset) {
				try {
					log.debug("Destroying key '{}' in keyset '{}'", key.id(), keyset.name());
					store.destroy(keyset.name(), key.id());
				} catch (Exception e) {
					log.error("Failed to destroy key '{}' in keyset '{}'", key.id(), keyset.name(), e);
				}
			}
		}
	}

}
