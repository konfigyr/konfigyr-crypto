package com.konfigyr.crypto;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.AutoConfigureAfter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.scheduling.annotation.EnableScheduling;

/**
 * Autoconfiguration class that registers {@link KeysetTaskRegistration} beans for
 * automatic key lifecycle maintenance when both a {@link KeysetStore} and a
 * {@link KeysetRepository} are present in the application context.
 * <p>
 * Two maintenance tasks are registered by default:
 * <ul>
 *     <li><em>keyset-rotation</em> — creates the next key of every keyset whose primary key
 *     expires within its {@link KeysetDefinition#getRotationLeadTime() rotation lead time}, then
 *     calls {@link KeysetStore#rotate(String)} for every keyset whose primary key's
 *     {@link EncryptedKey#expiresAt() expiry time} has elapsed. Controlled via
 *     {@code konfigyr.crypto.tasks.keyset-rotation.*}.</li>
 *     <li><em>keyset-destruction</em> — calls
 *     {@link KeysetStore#destroy(String, String)} for every key whose
 *     {@link KeyStatus#PENDING_DESTRUCTION} or {@link KeyStatus#COMPROMISED_PENDING_DESTRUCTION}
 *     grace period has elapsed. Controlled via
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
@EnableScheduling
@AutoConfiguration
@AutoConfigureAfter(CryptoAutoConfiguration.class)
@ConditionalOnBean({KeysetStore.class, KeysetRepository.class})
public class KeysetTaskAutoConfiguration {

	private final Environment environment;
	private final KeysetStore keysetStore;
	private final KeysetRepository keysetRepository;

	KeysetTaskAutoConfiguration(Environment environment, KeysetStore keysetStore, KeysetRepository keysetRepository) {
		this.environment = environment;
		this.keysetStore = keysetStore;
		this.keysetRepository = keysetRepository;
	}

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

}
