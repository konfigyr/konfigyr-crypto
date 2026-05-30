package com.konfigyr.crypto;

import org.jspecify.annotations.NullMarked;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.Assert;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import static com.konfigyr.crypto.CryptoException.*;

/**
 * Default implementation of the {@link KeysetStore} which uses a single
 * {@link KeysetRepository} implementation to store and retrieve cryptographic keys.
 * <p>
 * Leverages multiple {@link KeyEncryptionKeyProvider KEK providers} from where it can
 * extract the required {@link KeyEncryptionKey} to wrap or unwrap {@link Keyset Data
 * Encryption Keys}.
 * <p>
 * Can use more than one implementation of a {@link KeysetFactory} that is responsible for
 * generating the {@link Keyset keysets} and defines which {@link Algorithm algorithms}
 * are supported when performing {@link KeysetOperation cryptographic operatins}.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
@NullMarked
public class RepostoryKeysetStore implements KeysetStore {

	private final Logger logger = LoggerFactory.getLogger(getClass());

	private final KeysetCache cache;

	private final KeysetRepository repository;

	private final List<KeysetFactory> factories;

	private final List<KeyEncryptionKeyProvider> providers;

	/**
	 * Creates a new {@link RepostoryKeysetStore} instance using the provided arguments.
	 *
	 * @param cache the keyset cache implementation, can't be {@literal null}
	 * @param repository the keyset repository implementation, can't be {@literal null}
	 * @param factories the list of keyset factories, can't be {@literal null}
	 * @param providers the list of key encryption key providers, can't be {@literal null}
	 */
	public RepostoryKeysetStore(
		KeysetCache cache,
		KeysetRepository repository,
		List<KeysetFactory> factories,
		List<KeyEncryptionKeyProvider> providers
	) {
		this.cache = cache;
		this.repository = repository;
		this.factories = Collections.unmodifiableList(factories);
		this.providers = Collections.unmodifiableList(providers);
	}

	@Override
	public Optional<KeyEncryptionKeyProvider> provider(String provider) {
		return providers.stream().filter(it -> Objects.equals(provider, it.getName())).findFirst();
	}

	@Override
	public Keyset create(String provider, String kek, KeysetDefinition definition) {
		Assert.hasText(provider, "Provider name must not be blank");
		Assert.hasText(kek, "Key encryption key ID must not be blank");

		final KeysetFactory factory = lookupFactory(definition);

		return create(factory, kek(provider, kek), definition);
	}

	@Override
	public Keyset create(KeyEncryptionKey kek, KeysetDefinition definition) {
		final KeysetFactory factory = lookupFactory(definition);

		return create(factory, kek, definition);
	}

	@Override
	public Keyset read(String name) {
		Assert.hasText(name, "Keyset name must not be blank");

		final EncryptedKeyset encryptedKeyset = lookupKeyset(name);
		final KeysetFactory factory = lookupFactory(encryptedKeyset);

		return read(factory, encryptedKeyset);
	}

	@Override
	public void write(Keyset keyset) {
		final KeysetFactory factory = lookupFactory(keyset);

		write(factory, keyset);
	}

	@Override
	public void rotate(String name) {
		Assert.hasText(name, "Keyset name must not be blank");

		final EncryptedKeyset encryptedKeyset = lookupKeyset(name);

		rotate(read(lookupFactory(encryptedKeyset), encryptedKeyset));
	}

	@Override
	public void rotate(Keyset keyset) {
		rotate(lookupFactory(keyset), keyset);
	}

	@Override
	public void rotate(String name, KeyDefinition definition) {
		Assert.hasText(name, "Keyset name must not be blank");

		final EncryptedKeyset encryptedKeyset = lookupKeyset(name);

		rotate(read(lookupFactory(encryptedKeyset), encryptedKeyset), definition);
	}

	@Override
	public void rotate(Keyset keyset, KeyDefinition definition) {
		if (keyset.getPurpose() != definition.getAlgorithm().purpose()) {
			throw new CryptoException.UnsupportedAlgorithmException(definition.getAlgorithm());
		}
		rotate(lookupFactory(keyset), keyset, definition);
	}

	@Override
	public void remove(String name) {
		Assert.hasText(name, "Keyset name must not be blank");

		if (logger.isDebugEnabled()) {
			logger.debug("Removing encrypted keyset data with name: {}", name);
		}

		try {
			repository.remove(name);
		}
		catch (IOException e) {
			throw new KeysetException(name, "Could not remove encrypted keyset with name: " + name, e);
		}

		cache.evict(name);
	}

	@Override
	public void remove(Keyset keyset) {
		remove(keyset.getName());
	}

	@Override
	public void disable(String keysetName, String keyId) {
		Assert.hasText(keysetName, "Keyset name must not be blank");
		Assert.hasText(keyId, "Key ID must not be blank");

		performKeyTransition(keysetName, keyset -> KeyTransition.disable(keyset, keyId));
	}

	@Override
	public void enable(String keysetName, String keyId) {
		Assert.hasText(keysetName, "Keyset name must not be blank");
		Assert.hasText(keyId, "Key ID must not be blank");

		performKeyTransition(keysetName, keyset -> KeyTransition.enable(keyset, keyId));
	}

	@Override
	public void compromise(String keysetName, String keyId) {
		Assert.hasText(keysetName, "Keyset name must not be blank");
		Assert.hasText(keyId, "Key ID must not be blank");

		performKeyTransition(keysetName, keyset -> KeyTransition.compromise(keyset, keyId));
	}

	@Override
	public void scheduleDestruction(String keysetName, String keyId) {
		Assert.hasText(keysetName, "Keyset name must not be blank");
		Assert.hasText(keyId, "Key ID must not be blank");

		performKeyTransition(keysetName, keyset -> {
			final Duration gracePeriod = keyset.getDestructionGracePeriod();

			if (gracePeriod != null) {
				return KeyTransition.scheduleDestruction(keyset, keyId, Instant.now().plus(gracePeriod));
			}

			return KeyTransition.destroy(keyset, keyId, Instant.now());
		});
	}

	@Override
	public void scheduleDestruction(String keysetName, String keyId, Instant destructionTime) {
		Assert.hasText(keysetName, "Keyset name must not be blank");
		Assert.hasText(keyId, "Key ID must not be blank");
		Assert.isTrue(destructionTime.isAfter(Instant.now()), "Destruction time must be in the future");

		performKeyTransition(keysetName, keyset -> KeyTransition.scheduleDestruction(keyset, keyId, destructionTime));
	}

	@Override
	public void cancelDestruction(String keysetName, String keyId) {
		Assert.hasText(keysetName, "Keyset name must not be blank");
		Assert.hasText(keyId, "Key ID must not be blank");

		performKeyTransition(keysetName, keyset -> KeyTransition.cancelDestruction(keyset, keyId));
	}

	@Override
	public void destroy(String keysetName, String keyId) {
		Assert.hasText(keysetName, "Keyset name must not be blank");
		Assert.hasText(keyId, "Key ID must not be blank");

		performKeyTransition(keysetName, keyset -> KeyTransition.destroy(keyset, keyId, Instant.now()));
	}

	/**
	 * Looks up the key within the keyset, validates the status transition using
	 * {@link KeyStatus#canTransitionTo(KeyStatus)}, delegates to the repository, and evicts
	 * the cache entry.
	 */
	private void performKeyTransition(String keysetName, Function<EncryptedKeyset, KeyTransition> transitionFactory) {
		final EncryptedKeyset encryptedKeyset = lookupKeyset(keysetName);
		final KeyTransition transition = transitionFactory.apply(encryptedKeyset);
		final String keyId = transition.getKeyId();

		final EncryptedKey key = encryptedKeyset.getKey(keyId).orElseThrow(
			() -> new KeyNotFoundException(keysetName, keyId)
		);

		if (!key.getStatus().canTransitionTo(transition.getStatus())) {
			throw new InvalidKeyStatusTransitionException(keysetName, keyId, key.getStatus(),
				transition.getStatus());
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Transitioning key '{}' in keyset '{}' from {} to {}", keyId, keysetName,
				key.getStatus(), transition.getStatus());
		}

		try {
			repository.updateKeyStatus(transition);
		} catch (IOException e) {
			throw new KeysetException(keysetName,
				"Could not update status of key '" + keyId + "' in keyset '" + keysetName + "'.", e);
		}

		cache.evict(keysetName);
	}

	/**
	 * Performs a {@link KeysetRepository} lookup for an {@link EncryptedKeyset} with a
	 * matching name.
	 * <p>
	 * If no such {@link EncryptedKeyset} is found, an {@link KeysetNotFoundException}
	 * must be thrown.
	 * @param name keyset name to be looked up, can't be {@literal null}
	 * @return matching keyset from the repository
	 * @throws KeysetNotFoundException when no such keyset exists in the repository
	 */
	protected EncryptedKeyset lookupKeyset(String name) {
		if (logger.isDebugEnabled()) {
			logger.debug("Looking up encrypted keyset with name: {}", name);
		}

		return cache.get(name, () -> {
			try {
				return repository.read(name).orElseThrow(() -> new KeysetNotFoundException(name));
			}
			catch (IOException e) {
				throw new KeysetException(name, "Could not read encrypted keyset with name: " + name, e);
			}
		});
	}

	/**
	 * Attempts to resolve the {@link KeysetFactory} that supports this
	 * {@link KeysetDefinition}.
	 * @param definition definition for which the factory is looked up, can't be
	 * {@literal null}
	 * @return supported keyset factor
	 * @throws UnsupportedKeysetException when no factory supports the definition
	 */
	protected KeysetFactory lookupFactory(KeysetDefinition definition) {
		return factories.stream()
			.filter(it -> it.supports(definition))
			.findFirst()
			.orElseThrow(() -> new UnsupportedKeysetException(definition));
	}

	/**
	 * Attempts to resolve the {@link KeysetFactory} that supports this
	 * {@link EncryptedKeyset}.
	 * @param encryptedKeyset keyset for which the factory is looked up, can't be
	 * {@literal null}
	 * @return supported keyset factor
	 * @throws UnsupportedKeysetException when no factory supports the keyset
	 */
	protected KeysetFactory lookupFactory(EncryptedKeyset encryptedKeyset) {
		return factories.stream()
			.filter(it -> it.supports(encryptedKeyset))
			.findFirst()
			.orElseThrow(() -> new UnsupportedKeysetException(encryptedKeyset));
	}

	/**
	 * Attempts to resolve the {@link KeysetFactory} that supports this {@link Keyset}.
	 * @param keyset keyset for which the factory is looked up, can't be {@literal null}
	 * @return supported keyset factory
	 * @throws UnsupportedKeysetException when no factory supports the keyset
	 */
	protected KeysetFactory lookupFactory(Keyset keyset) {
		return factories.stream()
			.filter(it -> Objects.equals(it.getName(), keyset.getFactory()))
			.findFirst()
			.orElseThrow(() -> new UnsupportedKeysetException(keyset));
	}

	/**
	 * Attempts to generate a new {@link Keyset keyset material} using the given
	 * {@link KeysetFactory} and {@link KeysetDefinition}.
	 * @param factory factory used to create the keyset, can't be {@literal null}
	 * @param kek key encryption key for this DEK, can't be {@literal null}
	 * @param definition definition to be used when creating a new keyset, can't be
	 * {@literal null}.
	 * @return generated keyset
	 */
	protected Keyset create(KeysetFactory factory, KeyEncryptionKey kek, KeysetDefinition definition) {
		if (logger.isDebugEnabled()) {
			logger.debug("Attempting to generate Keyset with [definition={}, kek={}]", definition,
					KeyEncryptionKey.format(kek));
		}

		final Keyset keyset;

		try {
			keyset = factory.create(kek, definition);
		}
		catch (IOException e) {
			throw new KeysetException(definition, "Fail to create keyset with name '" + definition.getName()
					+ "', algorithm '" + definition.getAlgorithm() + "' using KEK '" + kek + ".", e);
		}

		write(factory, keyset);

		return keyset;
	}

	/**
	 * Attempts to read the {@link EncryptedKeyset encrypted keyset material} and create a
	 * {@link Keyset} using the responsible {@link KeysetFactory}.
	 * @param factory factory used to create the keyset, can't be {@literal null}
	 * @param encryptedKeyset encrypted keyset material used to create the keyset, can't
	 * be {@literal null}
	 * @return decrypted keyset
	 */
	protected Keyset read(KeysetFactory factory, EncryptedKeyset encryptedKeyset) {
		if (logger.isDebugEnabled()) {
			logger.debug("Reading encrypted keyset data with name: {}", encryptedKeyset.getName());
		}

		final KeyEncryptionKeyProvider provider = provider(encryptedKeyset.getProvider())
			.orElseThrow(() -> new ProviderNotFoundException(encryptedKeyset.getProvider()));

		final KeyEncryptionKey kek = provider.provide(encryptedKeyset);

		try {
			return factory.create(kek, encryptedKeyset);
		}
		catch (IOException e) {
			throw new UnwrappingException(encryptedKeyset.getName(), kek, e);
		}
	}

	/**
	 * Attempts to write the given {@link Keyset} in the {@link KeysetRepository} in form
	 * of a {@link EncryptedKeyset} using the responsible {@link KeysetFactory}.
	 * @param factory factory used to encrypt the keyset, can't be {@literal null}
	 * @param keyset keyset material to be written, can't be {@literal null}
	 */
	protected void write(KeysetFactory factory, Keyset keyset) {
		final EncryptedKeyset encryptedKeyset;

		try {
			encryptedKeyset = factory.create(keyset);
		}
		catch (IOException e) {
			throw new WrappingException(keyset.getName(), keyset.getKeyEncryptionKey(), e);
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Writing encrypted keyset data for: {}", keyset.getName());
		}

		final EncryptedKeyset written;

		try {
			written = repository.write(encryptedKeyset);
		}
		catch (IOException e) {
			throw new KeysetException(keyset.getName(),
					"Could not write encrypted keyset with name: " + keyset.getName(), e);
		}

		cache.put(written.getName(), written);
	}

	/**
	 * Attempts to rotate the key material of the given {@link Keyset} and writes the
	 * updates in the {@link KeysetRepository} in form of a {@link EncryptedKeyset} using
	 * the responsible {@link KeysetFactory}.
	 * @param factory factory used to encrypt the keyset, can't be {@literal null}
	 * @param keyset keyset to be rotated, can't be {@literal null}
	 */
	protected void rotate(KeysetFactory factory, Keyset keyset) {
		if (logger.isDebugEnabled()) {
			logger.debug("Attempting to rotate keyset with name: {}", keyset.getName());
		}

		final Keyset rotated = keyset.rotate();

		write(factory, rotated);

		if (logger.isDebugEnabled()) {
			logger.debug("Keyset '{}' has been successfully rotated.", rotated.getName());
		}
	}

	/**
	 * Attempts to rotate the key material of the given {@link Keyset} using the provided
	 * {@link KeyDefinition} and writes the result to the {@link KeysetRepository} using
	 * the responsible {@link KeysetFactory}.
	 * @param factory    factory used to encrypt the keyset, can't be {@literal null}
	 * @param keyset     keyset to be rotated, can't be {@literal null}
	 * @param definition parameters for the new key, can't be {@literal null}
	 */
	protected void rotate(KeysetFactory factory, Keyset keyset, KeyDefinition definition) {
		if (logger.isDebugEnabled()) {
			logger.debug("Attempting to rotate keyset '{}' with definition: {}", keyset.getName(), definition);
		}

		final Keyset rotated = keyset.rotate(definition);

		write(factory, rotated);

		if (logger.isDebugEnabled()) {
			logger.debug("Keyset '{}' has been successfully rotated with: {}", rotated.getName(), definition);
		}
	}

}
