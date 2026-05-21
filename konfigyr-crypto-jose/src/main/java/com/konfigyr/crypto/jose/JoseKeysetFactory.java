package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import com.nimbusds.jose.jwk.JWK;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NullMarked;

import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of the {@link KeysetFactory} that integrates
 * <a href="https://connect2id.com/products/nimbus-jose-jwt">Nimbus JOSE SDK</a> in the Konfigyr {@link KeysetStore}.
 * <p>
 * It produces the {@link JsonWebKeyset} implementation that would be using the set of {@link JWK JWKs} as the
 * underlying store of cryptographic keys. To generate a new {@link JsonWebKeyset} it is required to use a
 * {@link JoseAlgorithm} when defining which type of keys should be generated to perform specified
 * {@link KeysetOperation key operations}.
 * <p>
 * You can use the {@link JsonWebKeyset} as a {@link com.nimbusds.jose.jwk.source.JWKSource} to retrieve
 * JSON Web cryptographic keys from keyset. This makes it easier to integrate the keysets in the Nimbus SDK
 * API, like {@link com.nimbusds.jose.proc.JWEKeySelector JWEKeySelector} and
 * {@link com.nimbusds.jose.proc.JWSKeySelector JWSKeySelector}.
 * <p>
 * Keep in mind that the {@link JsonWebKeyset} generates a {@link com.nimbusds.jose.JWEObject JWE}
 * token when encrypting data using a {@link KeysetPurpose#ENCRYPTION} algorithm, and a
 * {@link com.nimbusds.jose.JWSObject JWS} token when signing data.
 *
 * @author : Vladimir Spasic
 * @since : 24.11.25, Mon
 * @see JoseAlgorithm
 * @see JsonWebKeyset
 **/
@NullMarked
@RequiredArgsConstructor
public class JoseKeysetFactory implements KeysetFactory {

	static final String NAME = "jose";

	private final AlgorithmRegistry registry;

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public boolean supports(KeysetDefinition definition) {
		return definition.getAlgorithm() instanceof JoseAlgorithm;
	}

	@Override
	public Keyset create(KeyEncryptionKey kek, KeysetDefinition definition) {
		return new JsonWebKeyset.Builder(definition)
			.key(JsonWebKey.generate(KeyDefinition.of(definition), JoseUtils.generateKeyId()))
			.keyEncryptionKey(kek)
			.build();
	}

	@Override
	public EncryptedKeyset create(Keyset keyset) {
		final KeyEncryptionKey kek = keyset.getKeyEncryptionKey();
		final List<EncryptedKey> keys = new ArrayList<>(keyset.getKeys().size());

		for (Key key : keyset.getKeys()) {
			final ByteArray encrypted;

			try {
				final JWK value = ((JsonWebKey) key).getValue();
				encrypted = kek.wrap(ByteArray.fromString(value.toJSONString()));
			} catch (Exception e) {
				throw new CryptoException.WrappingException(keyset.getName(), kek, e);
			}

			keys.add(EncryptedKey.from(key, encrypted));
		}

		return EncryptedKeyset.from(keyset, keys);
	}

	@Override
	public Keyset create(KeyEncryptionKey kek, EncryptedKeyset encryptedKeyset) {
		final JsonWebKeyset.Builder builder = new JsonWebKeyset.Builder(encryptedKeyset)
			.keyEncryptionKey(kek);

		for (EncryptedKey encrypted : encryptedKeyset) {
			final JWK key;

			try {
				final ByteArray unwrapped = kek.unwrap(encrypted.getData());
				key = JWK.parse(unwrapped.encode(String::new));
			} catch (Exception e) {
				throw new CryptoException.UnwrappingException(encryptedKeyset.getName(), kek, e);
			}

			final JoseAlgorithm algorithm = (JoseAlgorithm) registry.resolve(encrypted.getAlgorithm());

			builder.key(new JsonWebKey.Builder(key)
				.id(encrypted.getId())
				.status(encrypted.getStatus())
				.algorithm(algorithm)
				.primary(encrypted.isPrimary())
				.createdAt(encrypted.getCreatedAt())
				.initializedAt(encrypted.getInitializedAt())
				.expiresAt(encrypted.getExpiresAt())
				.destructionScheduledAt(encrypted.getDestructionScheduledAt())
				.destroyedAt(encrypted.getDestroyedAt())
				.build()
			);
		}

		return builder.build();
	}
}
