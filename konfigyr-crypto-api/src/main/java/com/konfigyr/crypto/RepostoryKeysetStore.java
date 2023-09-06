package com.konfigyr.crypto;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cache.Cache;
import org.springframework.lang.NonNull;

import java.io.IOException;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

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
 * @author : Vladimir Spasic
 * @since : 26.08.23, Sat
 **/
@RequiredArgsConstructor
public final class RepostoryKeysetStore implements KeysetStore {

	private final Logger logger = LoggerFactory.getLogger(getClass());

	private final KeysetCache cache;

	private final KeysetRepository repository;

	private final List<KeysetFactory> factories;

	private final List<KeyEncryptionKeyProvider> providers;

	@NonNull
	@Override
	public Optional<KeyEncryptionKeyProvider> provider(@NonNull String provider) {
		return providers.stream().filter(it -> Objects.equals(provider, it.getName())).findFirst();
	}

	@NonNull
	@Override
	public Keyset create(@NonNull String provider, @NonNull String kek, @NonNull KeysetDefinition definition) {
		final KeysetFactory factory = lookupFactory(definition);

		return create(factory, kek(provider, kek), definition);
	}

	@NonNull
	@Override
	public Keyset create(@NonNull KeyEncryptionKey kek, @NonNull KeysetDefinition definition) {
		final KeysetFactory factory = lookupFactory(definition);

		return create(factory, kek, definition);
	}

	@NonNull
	@Override
	public Keyset read(@NonNull String name) {
		final EncryptedKeyset encryptedKeyset = lookupKeyset(name);
		final KeysetFactory factory = lookupFactory(encryptedKeyset);

		return read(factory, encryptedKeyset);
	}

	@Override
	public void write(@NonNull Keyset keyset) {
		final KeysetFactory factory = lookupFactory(keyset);

		write(factory, keyset);
	}

	@Override
	public void rotate(@NonNull String name) {
		final EncryptedKeyset encryptedKeyset = lookupKeyset(name);
		final KeysetFactory factory = lookupFactory(encryptedKeyset);

		rotate(factory, read(factory, encryptedKeyset));
	}

	@Override
	public void rotate(@NonNull Keyset keyset) {
		rotate(lookupFactory(keyset), keyset);
	}

	@Override
	public void remove(@NonNull String name) {
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
	public void remove(@NonNull Keyset keyset) {
		remove(keyset.getName());
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
	protected @NonNull EncryptedKeyset lookupKeyset(@NonNull String name) {
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
	protected @NonNull KeysetFactory lookupFactory(@NonNull KeysetDefinition definition) {
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
	protected @NonNull KeysetFactory lookupFactory(@NonNull EncryptedKeyset encryptedKeyset) {
		return factories.stream()
			.filter(it -> it.supports(encryptedKeyset))
			.findFirst()
			.orElseThrow(() -> new UnsupportedKeysetException(encryptedKeyset));
	}

	/**
	 * Attempts to generate a new {@link Keyset keyset material} using the given
	 * {@link KeysetFactory} and {@link KeysetDefinition}.
	 * @param factory factory used to create the keyset, can't be {@literal null}
	 * @param kek key encryption key for this DEK,, can't be {@literal null}
	 * @param definition definition to be used when creating a new keyset, can't be
	 * {@literal null}.
	 * @return generated keyset
	 */
	protected @NonNull Keyset create(@NonNull KeysetFactory factory, @NonNull KeyEncryptionKey kek,
			@NonNull KeysetDefinition definition) {
		if (logger.isDebugEnabled()) {
			logger.debug("Attempting to generate Keyset with [definition={}, kek={}]", definition, kek);
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
	protected @NonNull Keyset read(@NonNull KeysetFactory factory, @NonNull EncryptedKeyset encryptedKeyset) {
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
	protected void write(@NonNull KeysetFactory factory, @NonNull Keyset keyset) {
		final EncryptedKeyset encryptedKeyset;

		try {
			encryptedKeyset = factory.create(keyset);
		}
		catch (IOException e) {
			throw new WrappingException(keyset.getName(), keyset.getKeyEncryptionKey(), e);
		}

		if (logger.isDebugEnabled()) {
			logger.debug("Writing encrypted keyset data for: {}", keyset);
		}

		try {
			repository.write(encryptedKeyset);
		}
		catch (IOException e) {
			throw new KeysetException(keyset.getName(),
					"Could not write encrypted keyset with name: " + keyset.getName(), e);
		}

		cache.put(encryptedKeyset.getName(), encryptedKeyset);
	}

	/**
	 * Attempts to rotate the key material of the given {@link Keyset} and writes the
	 * updates in the {@link KeysetRepository} in form of a {@link EncryptedKeyset} using
	 * the responsible {@link KeysetFactory}.
	 * @param factory factory used to encrypt the keyset, can't be {@literal null}
	 * @param keyset keyset to be rotated, can't be {@literal null}
	 */
	protected void rotate(@NonNull KeysetFactory factory, @NonNull Keyset keyset) {
		if (logger.isDebugEnabled()) {
			logger.debug("Attempting to rotate keyset with name: {}", keyset.getName());
		}

		final Keyset rotated = keyset.rotate();

		write(factory, rotated);

		if (logger.isDebugEnabled()) {
			logger.debug("Keyset '{}' has been successfully rotated, next rotation time is scheduled at: {}",
					rotated.getName(), rotated.getNextRotationTime());
		}
	}

}
