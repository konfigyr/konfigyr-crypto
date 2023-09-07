package com.konfigyr.crypto;

import org.springframework.lang.NonNull;

import java.util.Optional;

/**
 * Interface that defines how should management of cryptographic keys within an
 * application be performed in a secure manner. It focuses on these four main aspects of
 * key management:
 * <ul>
 * <li>Key selection</li>
 * <li>Key storage</li>
 * <li>Key rotation</li>
 * </ul>
 *
 * <h2>Key selection</h2>
 *
 * Library should provide a way for developers to choose which cryptographic algorithms
 * should they use within their application. This is defined by the
 * {@link KeysetDefinition} which contains the chosen {@link Algorithm} and its rotation
 * frequency.
 * <p>
 * The developer should select a specific Konfigyr library that defines the implementation
 * of the {@link Keyset} and the {@link Algorithm cryptographic algorithms} that best
 * suite their needs.
 * <p>
 * It is important to understand that a single {@link Keyset} should be used for only one
 * purpose (e.g., encryption, authentication, key wrapping, random number generation, or
 * digital signatures). The implementations of the {@link Algorithm} should make sure that
 * this does not happen by introducing a list of {@link KeysetOperation} that one
 * {@link Keyset} can perform.
 *
 * <h2>Key storage</h2>
 *
 * Choosing where {@link Keyset cryptographic keys} are stored within the application is
 * not easy task. This library provides a way to define your custom storage of
 * cryptographic material using the {@link KeysetRepository}.
 * <p>
 * The repository ensures that the cryptographic key material is protected on persistent
 * memory and never stored in plaintext format. The {@link Keyset} is encrypted using the
 * {@link KeyEncryptionKey} prior to the export of the key material.
 * <p>
 * It is recommended that the {@link KeyEncryptionKey} used to wrap on unwrap your
 * cryptographic key material are stored on a remote server, like KMS, and that these
 * cryptographic operations are done inside those servers.
 * <p>
 * If that is not possible, please make sure that the {@link KeyEncryptionKey} is provided
 * to your application in a secure way and that you never store it in the same place where
 * you store your {@link EncryptedKeyset eDEKs}.
 *
 * <h2>Key rotation</h2>
 *
 * It is important to understand that your {@link Keyset Data Encryption Keys} should be
 * changed (or rotated) based on a number of different criteria:
 * <ul>
 * <li>If the previous key is known (or suspected) to have been compromised</li>
 * <li>After a specified period of time has elapsed (known as the crypto period)</li>
 * <li>After the key has been used to encrypt a specific amount of data</li>
 * <li>If there is a significant change to the security provided by the algorithm</li>
 * </ul>
 *
 * The Konfigyr library defines the {@link Keyset keysets} in such a way that keys can be
 * quickly rotated in the event of a compromise, expired crypto period or when an
 * algorithm is no longer secure. You can access the state of each key within the
 * {@link Keyset} and check what is the key identifier, its status and algorithm.
 *
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 **/
public interface KeysetStore {

	/**
	 * Locate the {@link KeyEncryptionKeyProvider} by the matching key name from this
	 * store.
	 * @param provider key encryption key provider name, can't be {@literal null}
	 * @return matching {@link KeyEncryptionKeyProvider} or an empty {@link Optional}
	 */
	@NonNull
	Optional<KeyEncryptionKeyProvider> provider(@NonNull String provider);

	/**
	 * Locate the {@link KeyEncryptionKey} by the matching id from a
	 * {@link KeyEncryptionKeyProvider}.
	 * @param provider key encryption key provider name, can't be {@literal null}
	 * @param id key encryption key identifier, can't be {@literal null}
	 * @return matching {@link KeyEncryptionKey}, never {@literal null}
	 * @throws com.konfigyr.crypto.CryptoException.ProviderNotFoundException when provider
	 * with a given name does not exist
	 * @throws com.konfigyr.crypto.CryptoException.KeyEncryptionKeyNotFoundException when
	 * resolved provider could not resolve the {@link KeyEncryptionKey} with the given
	 * identifier
	 */
	default @NonNull KeyEncryptionKey kek(@NonNull String provider, @NonNull String id) {
		return provider(provider).orElseThrow(() -> new CryptoException.ProviderNotFoundException(provider))
			.provide(id);
	}

	/**
	 * Creates a new {@link Keyset} with a single primary key using the given
	 * {@link Algorithm}
	 * <p>
	 * To create a new {@link Keyset} you would need to specify the identifier of the
	 * {@link KeyEncryptionKey} that should be used to create one along with the name of
	 * the {@link KeyEncryptionKeyProvider} that manages the {@literal KEK}.
	 * @param provider key encryption key provider name that manages the KEK, can't be
	 * {@literal null}
	 * @param kek key encryption key used to wrap or unwrap the private key material,
	 * can't be {@literal null}.
	 * @param definition definition to be used when creating a new keyset, can't be
	 * {@literal null}.
	 * @return the generate {@link Keyset}, never {@literal null}
	 * @throws com.konfigyr.crypto.CryptoException.ProviderNotFoundException when provider
	 * with a given name does not exist
	 * @throws com.konfigyr.crypto.CryptoException.KeyEncryptionKeyNotFoundException when
	 * resolved provider could not resolve the {@link KeyEncryptionKey} with the given
	 * identifier
	 * @throws com.konfigyr.crypto.CryptoException.KeysetException when a {@link Keyset}
	 * could not be created
	 */
	@NonNull
	default Keyset create(@NonNull String provider, @NonNull String kek, @NonNull KeysetDefinition definition) {
		return create(kek(provider, kek), definition);
	}

	/**
	 * Creates a new {@link Keyset} with a single primary key using the given
	 * {@link Algorithm}
	 * <p>
	 * To create a new {@link Keyset} you would need to specify the identifier of the
	 * {@link KeyEncryptionKey} that should be used to create one along with the name of
	 * the {@link KeyEncryptionKeyProvider} that manages the {@literal KEK}.
	 * @param kek key encryption key used to wrap or unwrap the private key material,
	 * can't be {@literal null}.
	 * @param definition definition to be used when creating a new keyset, can't be
	 * {@literal null}.
	 * @return the generate {@link Keyset}, never {@literal null}
	 * @throws com.konfigyr.crypto.CryptoException.ProviderNotFoundException when provider
	 * with a given name does not exist
	 * @throws com.konfigyr.crypto.CryptoException.KeyEncryptionKeyNotFoundException when
	 * resolved provider could not resolve the {@link KeyEncryptionKey} with the given
	 * identifier
	 * @throws com.konfigyr.crypto.CryptoException.KeysetException when a {@link Keyset}
	 * could not be created
	 */
	@NonNull
	Keyset create(@NonNull KeyEncryptionKey kek, @NonNull KeysetDefinition definition);

	/**
	 * Locate the {@link Keyset} by the matching key name from this store.
	 * @param name key name, can't be {@literal null}
	 * @return matching {@link Keyset}
	 * @throws com.konfigyr.crypto.CryptoException.KeysetNotFoundException when keyset is
	 * not found in this store
	 */
	@NonNull
	Keyset read(@NonNull String name);

	/**
	 * Writes the data of the {@link Keyset} to the persistent storage.
	 * <p>
	 * It is advised that the private key material is encrypted using the Key Encryption
	 * Key {@code KEK} before they are stored.
	 * @param keyset keyset to be written, can't be {@literal null}
	 */
	void write(@NonNull Keyset keyset);

	/**
	 * Performs a rotation of a {@link Keyset} where a new primary key is replaced by a
	 * newly generated one.
	 * @param keyset keyset name to be rotated, can't be {@literal null}
	 */
	void rotate(@NonNull String keyset);

	/**
	 * Performs a rotation of a {@link Keyset} where a new primary key is replaced by a
	 * newly generated one.
	 * @param keyset keyset to be rotated, can't be {@literal null}
	 */
	void rotate(@NonNull Keyset keyset);

	/**
	 * Deletes the {@link Keyset} by the matching key name from the store.
	 * @param name keyset name to be removed, can't be {@literal null}
	 */
	void remove(@NonNull String name);

	/**
	 * Deletes the {@link Keyset} from the store.
	 * @param keyset keyset to be removed, can't be {@literal null}
	 */
	void remove(@NonNull Keyset keyset);

}
