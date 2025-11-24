package com.konfigyr.crypto;

import org.jspecify.annotations.NonNull;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.cache.Cache;
import org.springframework.cache.support.NoOpCache;
import org.springframework.context.annotation.Bean;

import java.util.List;

/**
 * Autoconfiguration class used to create the {@link KeysetStore}. This configuration
 * requires that the {@link KeysetFactory} Spring Bean is present in the application
 * context.
 * <p>
 * This configuration also declares an in-memory implementation of the
 * {@link KeysetRepository} that should not be used in production. It is recommended to
 * use a JDBC implementation or create your own implementation if you wish to use this
 * library in a productive system.
 *
 * @author : Vladimir Spasic
 * @since : 28.08.23, Mon
 **/
@AutoConfiguration
@ConditionalOnBean(KeysetFactory.class)
@ConditionalOnMissingBean(KeysetStore.class)
public class CryptoAutoConfiguration {

	@Bean
	@ConditionalOnMissingBean(KeysetRepository.class)
	KeysetRepository inMemoryKeysetRepository() {
		return new InMemoryKeysetRepository();
	}

	@Bean
	KeysetStore repositoryKeysetStore(
			KeysetRepository repository,
			ObjectProvider<@NonNull KeysetCache> cache,
			ObjectProvider<@NonNull KeysetFactory> factories,
			ObjectProvider<@NonNull KeyEncryptionKeyProvider> providers
	) {
		final KeysetCache keysetCache = cache.getIfAvailable(CryptoAutoConfiguration::createNoopKeysetCache);

		return new RepostoryKeysetStore(keysetCache, repository, collect(factories), collect(providers));
	}

	private static KeysetCache createNoopKeysetCache() {
		final Cache delegate = new NoOpCache("noop-keyset-cache");
		return new SpringKeysetCache(delegate);
	}

	private static <T> List<T> collect(ObjectProvider<@NonNull T> provider) {
		return provider.orderedStream().toList();
	}

}
