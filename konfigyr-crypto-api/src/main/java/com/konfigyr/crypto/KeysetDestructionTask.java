package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.List;

/**
 * Queries {@link KeysetRepository#findPendingDestruction()} and moves every key whose grace period has
 * elapsed to the next step of its lifecycle:
 * <ul>
 *     <li>keys pending destruction are destroyed using {@link KeysetStore#destroy(String, String)},</li>
 *     <li>{@link KeyStatus#RETIRED retired} keys are destroyed when the keyset uses the
 *     {@link RetirementPolicy#DESTROY} policy, or scheduled for destruction using
 *     {@link KeysetStore#scheduleDestruction(String, String)} when it uses the
 *     {@link RetirementPolicy#SCHEDULE_DESTRUCTION} policy. Retired keys of keysets that were switched to the
 *     {@link RetirementPolicy#RETAIN} policy are left untouched.</li>
 * </ul>
 * Failures for individual keys are caught and logged so that one failure does not prevent the remaining
 * keys from being processed. A {@link CryptoException.KeysetConcurrentModificationException} is expected
 * when the task runs on multiple nodes and another node already modified the keyset, it is only logged at
 * debug level.
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
					process(keyset, key);
				} catch (CryptoException.KeysetConcurrentModificationException e) {
					log.debug("Keyset '{}' was modified concurrently while processing key '{}', skipping it",
						keyset.name(), key.id());
				} catch (Exception e) {
					log.error("Failed to destroy key '{}' in keyset '{}'", key.id(), keyset.name(), e);
				}
			}
		}
	}

	private void process(EncryptedKeyset keyset, EncryptedKey key) {
		if (key.status() != KeyStatus.RETIRED) {
			log.debug("Destroying key '{}' in keyset '{}'", key.id(), keyset.name());
			store.destroy(keyset.name(), key.id());
			return;
		}

		switch (keyset.retirementPolicy()) {
			case DESTROY -> {
				log.debug("Destroying retired key '{}' in keyset '{}'", key.id(), keyset.name());
				store.destroy(keyset.name(), key.id());
			}
			case SCHEDULE_DESTRUCTION -> {
				log.debug("Scheduling destruction of retired key '{}' in keyset '{}'", key.id(), keyset.name());
				store.scheduleDestruction(keyset.name(), key.id());
			}
			case RETAIN -> log.debug("Keyset '{}' retains its retired keys, leaving key '{}' untouched",
				keyset.name(), key.id());
		}
	}

}
