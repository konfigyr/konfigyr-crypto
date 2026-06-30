package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.cache.Cache;

import java.util.function.Supplier;

/**
 * Implementation of the {@link KeysetCache} that uses Spring {@link Cache} implementation
 * as the actual cache store.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
@NullMarked
public class SpringKeysetCache implements KeysetCache {

	private final Cache cache;

	/**
	 * Creates a new {@link SpringKeysetCache} backed by the given Spring {@link Cache}.
	 *
	 * @param cache the backing Spring cache, can't be {@literal null}
	 */
	public SpringKeysetCache(Cache cache) {
		this.cache = cache;
	}

	@Override
	public synchronized EncryptedKeyset get(String key, Supplier<@Nullable EncryptedKeyset> supplier) {
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
	public synchronized void put(String key, EncryptedKeyset keyset) {
		cache.put(key, keyset);
	}

	@Override
	public synchronized void evict(String key) {
		cache.evict(key);
	}

}
