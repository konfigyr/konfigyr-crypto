package com.konfigyr.crypto;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.support.NoOpCache;

import static org.assertj.core.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class KeysetStoreBuilderTest {

	@Mock
	KeysetCache cache;

	@Mock
	KeysetRepository repository;

	@Mock
	KeysetFactory factory;

	@Mock
	KeyEncryptionKeyProvider provider;

	@Test
	@DisplayName("should create store with default cache and repository implementations")
	void buildUsingDefaultCacheAndRepository() {
		final var store = KeysetStore.builder()
			.factories(factory)
			.providers(provider)
			.build();

		assertThat(store)
			.isNotNull()
			.isInstanceOf(RepostoryKeysetStore.class);

		assertThat(store)
			.extracting("cache")
			.isInstanceOf(SpringKeysetCache.class)
			.extracting("cache")
			.isInstanceOf(NoOpCache.class);

		assertThat(store)
			.extracting("repository")
			.isInstanceOf(InMemoryKeysetRepository.class);
	}

	@Test
	@DisplayName("should create store with custom cache and repository implementations")
	void buildUsingCustomCacheAndRepository() {
		final var store = KeysetStore.builder()
			.cache(cache)
			.repository(repository)
			.factories(factory)
			.providers(provider)
			.build();

		assertThat(store)
			.isNotNull()
			.isInstanceOf(RepostoryKeysetStore.class);

		assertThat(store)
			.extracting("cache")
			.isEqualTo(cache);

		assertThat(store)
			.extracting("repository")
			.isEqualTo(repository);
	}

	@Test
	@DisplayName("should fail to create store when no keyset factories are specified")
	void requireFactories() {
		assertThatIllegalArgumentException()
			.isThrownBy(KeysetStore.builder()::build)
			.withMessageContaining("You need to specify at least one Keyset factory");
	}

	@Test
	@DisplayName("should fail to create store when no KEK providers are specified")
	void requireProviders() {
		assertThatIllegalArgumentException()
			.isThrownBy(KeysetStore.builder().factories(factory)::build)
			.withMessageContaining("You need to specify at least one key encryption key provider");
	}

}
