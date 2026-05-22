package com.konfigyr.crypto;

import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.EnableScheduling;

import java.io.IOException;
import java.util.List;

/**
 * Autoconfiguration class that registers {@link KeysetTaskRegistration} beans for
 * automatic key lifecycle maintenance when both a {@link KeysetStore} and a
 * {@link KeysetRepository} are present in the application context.
 * <p>
 * Two maintenance tasks are registered by default:
 * <ul>
 *     <li><em>keyset-rotation</em> — calls {@link KeysetStore#rotate(String)} for every
 *     keyset whose primary key's {@link EncryptedKey#getExpiresAt() expiry time} has
 *     elapsed. Controlled via {@code konfigyr.crypto.tasks.keyset-rotation.*}.</li>
 *     <li><em>keyset-destruction</em> — calls
 *     {@link KeysetStore#destroy(String, String)} for every key whose
 *     {@link KeyStatus#PENDING_DESTRUCTION} grace period has elapsed. Controlled via
 *     {@code konfigyr.crypto.tasks.keyset-destruction.*}.</li>
 * </ul>
 * <p>
 * Each task supports two trigger styles configurable via its properties prefix:
 * <ul>
 *     <li>{@code interval} — a {@link java.time.Duration} for a fixed-rate periodic trigger
 *     (default {@literal 1h})</li>
 *     <li>{@code cron} — a standard cron expression; when both are set, {@code cron} takes
 *     precedence</li>
 * </ul>
 * <p>
 * Individual tasks can be disabled by setting their {@code enabled} property to
 * {@literal false}:
 * <pre>
 * konfigyr.crypto.tasks.keyset-rotation.enabled=false
 * konfigyr.crypto.tasks.keyset-destruction.interval=PT30M
 * </pre>
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see KeysetTaskRegistration
 **/
@RequiredArgsConstructor
@EnableScheduling
@AutoConfiguration
@AutoConfigureAfter(CryptoAutoConfiguration.class)
@ConditionalOnBean({KeysetStore.class, KeysetRepository.class})
public class KeysetTaskAutoConfiguration {

	private final Environment environment;
	private final KeysetStore keysetStore;
	private final KeysetRepository keysetRepository;

	/**
	 * Registers the keyset rotation task, which queries for keysets whose primary key's
	 * expiry time has elapsed and calls {@link KeysetStore#rotate(String)} for each.
	 *
	 * @return the task registration, never {@literal null}
	 */
	@Bean
	@ConditionalOnProperty(name = "konfigyr.crypto.tasks.keyset-rotation.enabled", havingValue = "true", matchIfMissing = true)
	KeysetTaskRegistration keysetRotationTaskRegistration() {
		return KeysetTaskRegistration.of("keyset-rotation", environment, new KeysetRotationTask(keysetStore, keysetRepository));
	}

	/**
	 * Registers the keyset destruction task, which queries for keys whose destruction
	 * grace period has elapsed and calls {@link KeysetStore#destroy(String, String)} for each.
	 *
	 * @return the task registration, never {@literal null}
	 */
	@Bean
	@ConditionalOnProperty(name = "konfigyr.crypto.tasks.keyset-destruction.enabled", havingValue = "true", matchIfMissing = true)
	KeysetTaskRegistration keysetDestructionTaskRegistration() {
		return KeysetTaskRegistration.of("keyset-destruction", environment, new KeysetDestructionTask(keysetStore, keysetRepository));
	}

	/**
	 * Queries {@link KeysetRepository#findPendingRotation()} and calls
	 * {@link KeysetStore#rotate(String)} for every keyset whose rotation interval has
	 * elapsed. Failures for individual keysets are caught and logged so that one failure
	 * does not prevent the remaining keysets from being rotated.
	 */
	@Slf4j
	@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
	static final class KeysetRotationTask implements Runnable {

		private final KeysetStore store;
		private final KeysetRepository repository;

		@Override
		public void run() {
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
					log.debug("Rotating keyset '{}'", keyset.getName());
					store.rotate(keyset.getName());
				} catch (Exception e) {
					log.error("Failed to rotate keyset '{}'", keyset.getName(), e);
				}
			}
		}

	}

	/**
	 * Queries {@link KeysetRepository#findPendingDestruction()} and calls
	 * {@link KeysetStore#destroy(String, String)} for every key whose grace period has
	 * elapsed. Failures for individual keys are caught and logged so that one failure
	 * does not prevent the remaining keys from being destroyed.
	 */
	@Slf4j
	@RequiredArgsConstructor(access = AccessLevel.PACKAGE)
	static final class KeysetDestructionTask implements Runnable {

		private final KeysetStore store;
		private final KeysetRepository repository;

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
						log.debug("Destroying key '{}' in keyset '{}'", key.getId(), keyset.getName());
						store.destroy(keyset.getName(), key.getId());
					} catch (Exception e) {
						log.error("Failed to destroy key '{}' in keyset '{}'", key.getId(), keyset.getName(), e);
					}
				}
			}
		}

	}

}
