package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.cache.support.NoOpCache;
import org.springframework.util.Assert;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Interface that defines how management of cryptographic keys within an application should be performed
 * securely. It focuses on these four main aspects of key management:
 * <ul>
 * <li>Key selection</li>
 * <li>Key storage</li>
 * <li>Key rotation</li>
 * </ul>
 *
 * <h2>Key selection</h2>
 *
 * Library should provide a way for developers to choose which cryptographic algorithms they would like to use
 * within their application. This is defined by the {@link KeysetDefinition} which contains the chosen
 * {@link Algorithm} and its rotation frequency.
 * <p>
 * The developer should select a specific Konfigyr library that defines the implementation of the {@link Keyset}
 * and the {@link Algorithm cryptographic algorithms} that best suite their needs.
 * <p>
 * It is important to understand that a single {@link Keyset} should be used for only one purpose (e.g., encryption,
 * authentication, key wrapping, random number generation, or digital signatures). The implementations of the
 * {@link Algorithm} should make sure that this does not happen by introducing a list of {@link KeysetOperation}
 * that one {@link Keyset} can perform.
 *
 * <h2>Key storage</h2>
 *
 * Choosing where {@link Keyset cryptographic keys} are stored within the application is not easy task. This library
 * provides a way to define your custom storage of cryptographic material using the {@link KeysetRepository}.
 * <p>
 * The repository ensures that the cryptographic key material is protected on persistent memory and never stored in
 * plaintext format. The {@link Keyset} is encrypted using the {@link KeyEncryptionKey} prior to the export of the
 * key material.
 * <p>
 * It is recommended that the {@link KeyEncryptionKey} used to wrap on unwrap your cryptographic key material are
 * stored on a remote server, like KMS, and that these cryptographic operations are done inside those servers.
 * <p>
 * If that is not possible, please make sure that the {@link KeyEncryptionKey} is provided to your application
 * in a secure way and that you never store it in the same place where you store your {@link EncryptedKeyset eDEKs}.
 *
 * <h2>Key rotation</h2>
 *
 * It is important to understand that your {@link Keyset Data Encryption Keys} should be changed (or rotated) based
 * on a number of different criteria:
 * <ul>
 * 		<li>If the previous key is known (or suspected) to have been compromised</li>
 * 		<li>After a specified period of time has elapsed (known as the crypto period)</li>
 * 		<li>After the key has been used to encrypt a specific amount of data</li>
 * 		<li>If there is a significant change to the security provided by the algorithm</li>
 * </ul>
 *
 * The Konfigyr library defines the {@link Keyset keysets} in such a way that keys can be quickly rotated in the
 * event of a compromise, expired crypto period, when an algorithm is no longer secure. You can access the state
 * of each key within the {@link Keyset} and check what is the key identifier, its status, and algorithm.
 *
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 **/
@NullMarked
public interface KeysetStore {

	/**
	 * Creates a new {@link Builder} instance that can be used to create {@link KeysetStore} instances.
	 * <p>
	 * This builder would return an instance of {@link RepostoryKeysetStore} by default.
	 *
	 * @return the keyset store builder, never {@literal null}.
	 * @see RepostoryKeysetStore
	 */
	static Builder builder() {
		return new Builder();
	}

	/**
	 * Locate the {@link KeyEncryptionKeyProvider} by the matching key name from this
	 * store.
	 * @param provider key encryption key provider name, can't be {@literal null}
	 * @return matching {@link KeyEncryptionKeyProvider} or an empty {@link Optional}
	 */
	Optional<KeyEncryptionKeyProvider> provider(String provider);

	/**
	 * Locate the {@link KeyEncryptionKey} by the matching id from a {@link KeyEncryptionKeyProvider}.
	 *
	 * @param provider key encryption key provider name, can't be {@literal null}
	 * @param id key encryption key identifier, can't be {@literal null}
	 * @return matching {@link KeyEncryptionKey}, never {@literal null}
	 * @throws com.konfigyr.crypto.CryptoException.ProviderNotFoundException when a provider with a given name
	 * does not exist
	 * @throws com.konfigyr.crypto.CryptoException.KeyEncryptionKeyNotFoundException when resolved provider could
	 * not resolve the {@link KeyEncryptionKey} with the given identifier
	 */
	default KeyEncryptionKey kek(String provider, String id) {
		return provider(provider).orElseThrow(() -> new CryptoException.ProviderNotFoundException(provider))
			.provide(id);
	}

	/**
	 * Creates a new {@link Keyset} with a single primary key using the given {@link Algorithm}
	 * <p>
	 * To create a new {@link Keyset} you would need to specify the identifier of the
	 * {@link KeyEncryptionKey} that should be used to create one along with the name of
	 * the {@link KeyEncryptionKeyProvider} that manages the {@literal KEK}.
	 *
	 * @param provider key encryption key provider name that manages the KEK can't be {@literal null}
	 * @param kek key encryption key used to wrap or unwrap the private key material, can't be {@literal null}.
	 * @param definition definition to be used when creating a new keyset, can't be {@literal null}.
	 * @return the generated {@link Keyset}, never {@literal null}
	 * @throws com.konfigyr.crypto.CryptoException.ProviderNotFoundException when the provider with a given name
	 * does not exist
	 * @throws com.konfigyr.crypto.CryptoException.KeyEncryptionKeyNotFoundException when resolved provider could
	 * not resolve the {@link KeyEncryptionKey} with the given identifier
	 * @throws com.konfigyr.crypto.CryptoException.KeysetException when a {@link Keyset} could not be created
	 */
	default Keyset create(String provider, String kek, KeysetDefinition definition) {
		return create(kek(provider, kek), definition);
	}

	/**
	 * Creates a new {@link Keyset} with a single primary key using the given {@link Algorithm}
	 * <p>
	 * To create a new {@link Keyset} you would need to specify the identifier of the
	 * {@link KeyEncryptionKey} that should be used to create one along with the name of
	 * the {@link KeyEncryptionKeyProvider} that manages the {@literal KEK}.
	 *
	 * @param kek key encryption key used to wrap or unwrap the private key material, can't be {@literal null}.
	 * @param definition definition to be used when creating a new keyset, can't be {@literal null}.
	 * @return the generated {@link Keyset}, never {@literal null}
	 * @throws com.konfigyr.crypto.CryptoException.ProviderNotFoundException when the provider with a given name
	 * does not exist
	 * @throws com.konfigyr.crypto.CryptoException.KeyEncryptionKeyNotFoundException when resolved provider could
	 * not resolve the {@link KeyEncryptionKey} with the given identifier
	 * @throws com.konfigyr.crypto.CryptoException.KeysetException when a {@link Keyset} could not be created
	 */
	Keyset create(KeyEncryptionKey kek, KeysetDefinition definition);

	/**
	 * Locate the {@link Keyset} by the matching key name from this store.
	 *
	 * @param name key name, can't be {@literal null}
	 * @return matching {@link Keyset}
	 * @throws com.konfigyr.crypto.CryptoException.KeysetNotFoundException when a keyset with the given name is
	 * not found in this store
	 */
	Keyset read(String name);

	/**
	 * Writes the data of the {@link Keyset} to the persistent storage.
	 * <p>
	 * It is advised that the private key material is encrypted using the Key Encryption Key {@code KEK}
	 * before they are stored.
	 *
	 * @param keyset keyset to be written, can't be {@literal null}
	 */
	void write(Keyset keyset);

	/**
	 * Performs a rotation of a {@link Keyset} where a new primary key is replaced by a newly generated one.
	 *
	 * @param keyset keyset name to be rotated, can't be {@literal null}
	 */
	void rotate(String keyset);

	/**
	 * Performs a rotation of a {@link Keyset} where a new primary key is replaced by a newly generated one.
	 *
	 * @param keyset keyset to be rotated, can't be {@literal null}
	 */
	void rotate(Keyset keyset);

	/**
	 * Deletes the {@link Keyset} by the matching key name from the store.
	 *
	 * @param name keyset name to be removed, can't be {@literal null}
	 */
	void remove(String name);

	/**
	 * Deletes the {@link Keyset} from the store.
	 *
	 * @param keyset keyset to be removed, can't be {@literal null}
	 */
	void remove(Keyset keyset);

	/**
	 * Builder class used to create {@link KeysetStore} instances. This builder would return an instance of
	 * {@link RepostoryKeysetStore} by default.
	 */
	final class Builder {
		private @Nullable KeysetCache cache;
		private @Nullable KeysetRepository repository;
		private final List<KeysetFactory> factories;
		private final List<KeyEncryptionKeyProvider> providers;

		private Builder() {
			providers = new ArrayList<>();
			factories = new ArrayList<>();
		}

		/**
		 * Specify the {@link KeysetCache} to be used by the {@link KeysetStore}.
		 *
		 * @param cache keyset cache implementation, can't be {@literal null}.
		 * @return the builder instance, never {@literal null}.
		 */
		public Builder cache(KeysetCache cache) {
			this.cache = cache;
			return this;
		}

		/**
		 * Specify the {@link KeysetRepository} to be used by the {@link KeysetStore}.
		 *
		 * @param repository keyset repository implementation, can't be {@literal null}.
		 * @return the builder instance, never {@literal null}.
		 */
		public Builder repository(KeysetRepository repository) {
			this.repository = repository;
			return this;
		}

		/**
		 * Specify the {@link KeysetFactory} implementations to be used by the {@link KeysetStore}.
		 *
		 * @param factories keyset factory implementations, can't be {@literal null}.
		 * @return the builder instance, never {@literal null}.
		 */
		public Builder factories(KeysetFactory... factories) {
			return factories(List.of(factories));
		}

		/**
		 * Specify the {@link KeysetFactory} implementations to be used by the {@link KeysetStore}.
		 *
		 * @param factories keyset factory implementations, can't be {@literal null}.
		 * @return the builder instance, never {@literal null}.
		 */
		public Builder factories(Iterable<KeysetFactory> factories) {
			for (KeysetFactory factory : factories) {
				this.factories.add(factory);
			}
			return this;
		}

		/**
		 * Specify the {@link KeyEncryptionKeyProvider} implementations to be used by the {@link KeysetStore}.
		 *
		 * @param providers key encryption key provider implementations, can't be {@literal null}.
		 * @return the builder instance, never {@literal null}.
		 */
		public Builder providers(KeyEncryptionKeyProvider... providers) {
			return providers(List.of(providers));
		}

		/**
		 * Specify the {@link KeyEncryptionKeyProvider} implementations to be used by the {@link KeysetStore}.
		 *
		 * @param providers key encryption key provider implementations, can't be {@literal null}.
		 * @return the builder instance, never {@literal null}.
		 */
		public Builder providers(Iterable<KeyEncryptionKeyProvider> providers) {
			for (KeyEncryptionKeyProvider provider : providers) {
				this.providers.add(provider);
			}
			return this;
		}

		/**
		 * Creates a new {@link KeysetStore} instance using the arguments provided to the builder.
		 *
		 * @return the keyset stores instance, never {@literal null}.
		 * @throws IllegalArgumentException when required arguments are not set.
		 */
		public KeysetStore build() {
			Assert.notEmpty(factories, "You need to specify at least one Keyset factory");
			Assert.notEmpty(providers, "You need to specify at least one key encryption key provider");

			if (repository == null) {
				repository = new InMemoryKeysetRepository();
			}

			if (cache == null) {
				cache = new SpringKeysetCache(new NoOpCache("noop-keyset-cache"));
			}

			return new RepostoryKeysetStore(cache, repository, factories, providers);
		}
	}

}
