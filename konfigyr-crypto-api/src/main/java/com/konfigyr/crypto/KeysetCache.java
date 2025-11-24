package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import java.util.function.Supplier;

/**
 * Interface that defines how encrypted cryptographic material is cached.
 *
 * @author : Vladimir Spasic
 * @since : 06.09.23, Wed
 **/
@NullMarked
public interface KeysetCache {

	/**
	 * Retrieves the {@link EncryptedKeyset} with the specified cached key, obtaining that
	 * value from {@link Supplier} if it is not present.
	 * <p>
	 * If possible, implementations of this method should ensure that the loading
	 * operation is synchronized so that the specified supplying function is only called
	 * once in case of concurrent access on the same key.
	 * @param key the key for which the {@link EncryptedKeyset} is to be returned, can't
	 * be {@literal null}
	 * @param supplier function that would obtain the value if the cached value is not
	 * present in the cache, can't be {@literal null}
	 * @return cached encrypted keyset, never {@literal null}
	 */
	EncryptedKeyset get(String key, Supplier<@Nullable EncryptedKeyset> supplier);

	/**
	 * Stores the {@link EncryptedKeyset} value with the specified key in this cache.
	 * @param key the key for which the {@link EncryptedKeyset} is to be associated, can't
	 * be {@literal null}
	 * @param keyset the {@link EncryptedKeyset} value to be associated with the specified
	 * key
	 */
	void put(String key, EncryptedKeyset keyset);

	/**
	 * Evicts the {@link EncryptedKeyset} for this key from this cache if it is present.
	 * @param key the key for which the {@link EncryptedKeyset} is to be evicted, can't be
	 * {@literal null}
	 */
	void evict(String key);

}
