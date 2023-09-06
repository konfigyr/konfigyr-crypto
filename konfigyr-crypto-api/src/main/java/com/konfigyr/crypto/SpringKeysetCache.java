package com.konfigyr.crypto;

import lombok.RequiredArgsConstructor;
import org.springframework.cache.Cache;
import org.springframework.lang.NonNull;

import java.util.function.Supplier;

/**
 * Implementation of the {@link KeysetCache} that uses Spring {@link Cache} implementation
 * as the actual cache store.
 *
 * @author : Vladimir Spasic
 * @since : 06.09.23, Wed
 **/
@RequiredArgsConstructor
public class SpringKeysetCache implements KeysetCache {

	private final Cache cache;

	@Override
	public synchronized EncryptedKeyset get(@NonNull String key, @NonNull Supplier<EncryptedKeyset> supplier) {
		EncryptedKeyset encryptedKeyset = cache.get(key, EncryptedKeyset.class);

		if (encryptedKeyset != null) {
			return encryptedKeyset;
		}

		encryptedKeyset = supplier.get();

		if (encryptedKeyset == null) {
			throw new IllegalStateException("Keyset cache detected a null encrypted keyset value for " + "cache key '"
					+ key + "'. This is currently not supported by this cache implementation.");
		}

		put(key, encryptedKeyset);

		return encryptedKeyset;
	}

	@Override
	public synchronized void put(@NonNull String key, @NonNull EncryptedKeyset keyset) {
		cache.put(key, keyset);
	}

	@Override
	public synchronized void evict(@NonNull String key) {
		cache.evict(key);
	}

}
