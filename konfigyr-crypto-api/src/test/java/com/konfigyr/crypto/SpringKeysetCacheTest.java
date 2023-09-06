package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;

import java.time.Instant;
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
	void shouldRetrieveCachedKeysets() {
		final var keyset = createEncryptedKeyset("test-keyset");
		doReturn(keyset).when(supplier).get();

		assertThat(cache.get(keyset.getName(), supplier)).isEqualTo(keyset);
		assertThat(cache.get(keyset.getName(), supplier)).isEqualTo(keyset);

		verify(supplier).get();
		verify(delegate, times(2)).get(eq(keyset.getName()), eq(EncryptedKeyset.class));
	}

	@Test
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
	void shouldNotStoreNullKeysets() {
		assertThatThrownBy(() -> cache.get("cache-key", supplier)).isInstanceOf(IllegalStateException.class)
			.hasNoCause()
			.hasMessageContaining("Keyset cache detected a null encrypted keyset value for cache key 'cache-key'");

		verify(supplier).get();
		verify(delegate).get(eq("cache-key"), eq(EncryptedKeyset.class));
	}

	private static EncryptedKeyset createEncryptedKeyset(String name) {
		return EncryptedKeyset.builder()
			.name(name)
			.algorithm("test-algorithm")
			.provider("test-provider")
			.keyEncryptionKey("test-kek")
			.rotationInterval(60)
			.nextRotationTime(Instant.now())
			.build(ByteArray.fromString("encrypted material for " + name));
	}

}
