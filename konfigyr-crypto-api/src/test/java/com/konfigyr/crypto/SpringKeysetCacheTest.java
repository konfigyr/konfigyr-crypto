package com.konfigyr.crypto;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;

import java.time.Duration;
import java.util.List;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SpringKeysetCacheTest {

	@Spy
	Cache delegate = new ConcurrentMapCache("test-cache");

	@Mock
	Supplier<EncryptedKeyset> supplier;

	KeysetCache cache;

	@BeforeEach
	void setup() {
		cache = new SpringKeysetCache(delegate);
	}

	@Test
	@DisplayName("should retrieve a cached keyset without invoking the supplier more than once")
	void shouldRetrieveCachedKeysets() {
		final var keyset = createEncryptedKeyset("test-keyset");
		doReturn(keyset).when(supplier).get();

		assertThat(cache.get(keyset.getName(), supplier)).isEqualTo(keyset);
		assertThat(cache.get(keyset.getName(), supplier)).isEqualTo(keyset);

		verify(supplier).get();
		verify(delegate, times(2)).get(eq(keyset.getName()), eq(EncryptedKeyset.class));
	}

	@Test
	@DisplayName("should store a keyset in the cache and evict it by key")
	void shouldStoreKeysetInCacheAndEvict() {
		final var keyset = createEncryptedKeyset("testing-keyset");

		assertThatNoException().isThrownBy(() -> cache.put("cache-key", keyset));
		assertThat(cache.get("cache-key", supplier)).isEqualTo(keyset);
		assertThatNoException().isThrownBy(() -> cache.evict("cache-key"));

		verifyNoInteractions(supplier);
		verify(delegate).get(eq("cache-key"), eq(EncryptedKeyset.class));
		verify(delegate).put(eq("cache-key"), eq(keyset));
		verify(delegate).evict(eq("cache-key"));

		assertThat(delegate.get("cache-key")).isNull();
	}

	@Test
	@DisplayName("should throw when the supplier returns a null encrypted keyset")
	void shouldNotStoreNullKeysets() {
		assertThatIllegalStateException()
			.isThrownBy(() -> cache.get("cache-key", supplier))
			.withNoCause()
			.withMessageContaining("Keyset cache detected a null encrypted keyset value for cache key 'cache-key'");

		verify(supplier).get();
		verify(delegate).get(eq("cache-key"), eq(EncryptedKeyset.class));
	}

	private static EncryptedKeyset createEncryptedKeyset(String name) {
		return EncryptedKeyset.builder()
			.name(name)
			.purpose(KeysetPurpose.ENCRYPTION)
			.factory("test-factory")
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.rotationInterval(Duration.ofDays(90))
			.build(List.of());
	}

}
