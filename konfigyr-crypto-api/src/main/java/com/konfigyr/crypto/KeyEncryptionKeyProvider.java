package com.konfigyr.crypto;

import org.springframework.lang.NonNull;

import java.util.Collection;
import java.util.Set;

/**
 * Provider interface which provides a way to select and construct {@link KeyEncryptionKey
 * KEKs} for encrypting and decrypting Data Encryption Keys.
 * <p>
 * Application can have one or more implementations of the {@link KeyEncryptionKeyProvider
 * providers} identified by their unique provider names. If your application uses more
 * than one provider it is necessary that each provider name that is given to
 * {@link Keyset}s or {@link EncryptedKeyset}s can be uniquely identified and retrieved.
 *
 * @author : Vladimir Spasic
 * @since : 26.08.23, Sat
 **/
public interface KeyEncryptionKeyProvider {

	static KeyEncryptionKeyProvider of(String name, KeyEncryptionKey... keys) {
		return new SimpleKeyEncryptionKeyProvider(name, Set.of(keys));
	}

	static KeyEncryptionKeyProvider of(String name, Collection<KeyEncryptionKey> keys) {
		return new SimpleKeyEncryptionKeyProvider(name, keys);
	}

	/**
	 * Name is considered as the main identifier of a provider. When using multiple
	 * provider implementations within one application it is important that the names are
	 * unique.
	 * @return provider name, never {@link null}
	 */
	@NonNull
	String getName();

	/**
	 * Retrieves and constructs the {@link KeyEncryptionKey} used to decrypt the
	 * {@link EncryptedKeyset}.
	 * @param encryptedKeyset keyset for which the KEK should be provided, can't be
	 * {@literal null}
	 * @return the KEK for this keyset, never {@link null}
	 * @throws com.konfigyr.crypto.CryptoException.KeyEncryptionKeyNotFoundException when
	 * the provider could not resolve the {@link KeyEncryptionKey} with the given
	 * identifier
	 */
	default @NonNull KeyEncryptionKey provide(@NonNull EncryptedKeyset encryptedKeyset) {
		return provide(encryptedKeyset.getKeyEncryptionKey());
	}

	/**
	 * Retrieves and constructs the {@link KeyEncryptionKey} used to decrypt or encrypt
	 * the Data Encryption Keys by the provider name.
	 * @param id the identifier of the {@link KeyEncryptionKey}, can't be {@literal null}
	 * @return matching key encryption key, never {@link null}
	 * @throws com.konfigyr.crypto.CryptoException.KeyEncryptionKeyNotFoundException when
	 * the provider could not resolve the {@link KeyEncryptionKey} with the given
	 * identifier
	 */
	@NonNull
	KeyEncryptionKey provide(@NonNull String id);

}
