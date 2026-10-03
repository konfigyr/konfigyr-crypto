package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.Algorithm;
import com.konfigyr.crypto.AlgorithmRegistry;
import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.EncryptedKey;
import com.konfigyr.crypto.EncryptedKeyset;
import com.konfigyr.crypto.Key;
import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetFactory;
import com.konfigyr.crypto.WrappedKeyMaterial;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of the {@link KeysetFactory} that creates {@link Keyset keysets} of asymmetric key pairs
 * that are bound to self-signed X.509 certificates, using the {@link X509Algorithm X509 algorithms}.
 * <p>
 * The private key and the certificate chain of each key are encoded together and wrapped by the
 * {@link KeyEncryptionKey} of the keyset. Plaintext key material is never part of the produced
 * {@link EncryptedKeyset}.
 *
 * @author Vladimir Spasic
 * @since 1.1.0
 * @see X509Algorithm
 */
@NullMarked
public class X509KeysetFactory implements KeysetFactory {

	static final String NAME = "x509";

	private final AlgorithmRegistry registry;

	/**
	 * Creates a new {@link X509KeysetFactory} that resolves algorithms from the given registry.
	 *
	 * @param registry the algorithm registry used to look up {@link X509Algorithm} instances, can't be {@literal null}
	 */
	public X509KeysetFactory(AlgorithmRegistry registry) {
		this.registry = registry;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public boolean supports(KeysetDefinition definition) {
		return definition.getAlgorithm() instanceof X509Algorithm;
	}

	@Override
	public Keyset create(KeyEncryptionKey kek, KeysetDefinition definition) {
		final X509Key key = X509Key.generate(
			KeyDefinition.of(definition),
			X509Utils.generateKeyId(),
			definition.getName(),
			X509Utils.certificateNotAfter(
				Instant.now(),
				definition.getRotationInterval().orElse(null),
				definition.getDestructionGracePeriod().orElse(null)
			));

		return new X509Keyset.Builder(definition)
			.keyEncryptionKey(kek)
			.key(key)
			.build();
	}

	@Override
	public EncryptedKeyset create(Keyset keyset) {
		final KeyEncryptionKey kek = keyset.getKeyEncryptionKey();
		final List<EncryptedKey> keys = new ArrayList<>(keyset.getKeys().size());

		for (Key key : keyset.getKeys()) {
			final WrappedKeyMaterial encrypted;

			try {
				encrypted = kek.wrap(X509MaterialCodec.encode((X509Key) key));
			} catch (IOException | GeneralSecurityException ex) {
				throw new CryptoException.WrappingException(keyset.getName(), kek, ex);
			}

			keys.add(EncryptedKey.from(key, encrypted));
		}

		return EncryptedKeyset.from(keyset, keys);
	}

	@Override
	public Keyset create(KeyEncryptionKey kek, EncryptedKeyset encryptedKeyset) {
		final X509Keyset.Builder builder = new X509Keyset.Builder(encryptedKeyset)
			.keyEncryptionKey(kek);

		for (EncryptedKey encrypted : encryptedKeyset) {
			if (encrypted.data() == null) {
				continue;
			}

			final X509Algorithm algorithm = resolveAlgorithm(encrypted.algorithm());
			final X509Key.Builder key;

			try {
				final ByteArray unwrapped = kek.unwrap(encrypted.data());
				key = X509MaterialCodec.decode(unwrapped, algorithm);
			} catch (IOException | GeneralSecurityException ex) {
				throw new CryptoException.UnwrappingException(encryptedKeyset.name(), kek, ex);
			}

			builder.key(key
				.id(encrypted.id())
				.status(encrypted.status())
				.primary(encrypted.primary())
				.createdAt(encrypted.createdAt())
				.initializedAt(encrypted.initializedAt())
				.expiresAt(encrypted.expiresAt())
				.destructionScheduledAt(encrypted.destructionScheduledAt())
				.destroyedAt(encrypted.destroyedAt())
				.build()
			);
		}

		return builder.build();
	}

	private X509Algorithm resolveAlgorithm(String name) {
		final Algorithm algorithm = registry.resolve(name);

		if (algorithm instanceof X509Algorithm x509) {
			return x509;
		}

		throw new CryptoException.UnsupportedAlgorithmException(algorithm);
	}
}
