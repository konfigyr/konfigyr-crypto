package com.konfigyr.crypto.tink;

import com.google.crypto.tink.*;
import com.google.crypto.tink.ProtoKeySerialization;
import com.google.crypto.tink.internal.MutableSerializationRegistry;
import com.google.crypto.tink.internal.ProtoConversions;
import com.google.crypto.tink.proto.KeyData;
import com.google.protobuf.InvalidProtocolBufferException;
import com.konfigyr.crypto.*;
import com.konfigyr.crypto.Key;
import com.konfigyr.crypto.WrappedKeyMaterial;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;
import org.springframework.util.Assert;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Implementation of the {@link KeysetFactory} that integrates
 * <a href="https://developers.google.com/tink/">Google Tink</a> library in the Konfigyr {@link KeysetStore}.
 * <p>
 * It produces the {@link TinkKeyset} implementation that would be using the {@link KeysetHandle} as the underlying
 * store of cryptographic keys. To generate a new {@link TinkKeyset} it is required to use a {@link TinkAlgorithm}
 * when defining which type of keys should be generated and which Tink Primitives can be used to perform
 * specified {@link KeysetOperation key operations}.
 * <p>
 * When encrypting or decrypting the {@link KeysetHandle} a {@link TinkProtoKeysetFormat} would be used to
 * serialize the sensitive key material.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see TinkAlgorithm
 * @see TinkKeyset
 **/
@NullMarked
public class TinkKeysetFactory implements KeysetFactory {

	static final String NAME = "tink";

	private final AlgorithmRegistry registry;

	/**
	 * Creates a new {@link TinkKeysetFactory} that resolves algorithms from the given registry.
	 *
	 * @param registry the algorithm registry used to look up {@link TinkAlgorithm} instances, can't be {@literal null}
	 */
	public TinkKeysetFactory(AlgorithmRegistry registry) {
		this.registry = registry;
	}

	@Override
	public String getName() {
		return NAME;
	}

	@Override
	public boolean supports(KeysetDefinition definition) {
		return definition.getAlgorithm() instanceof TinkAlgorithm;
	}

	@Override
	public Keyset create(KeyEncryptionKey kek, KeysetDefinition definition) {
		return new TinkKeyset.Builder(definition)
			.key(TinkKey.generate(KeyDefinition.of(definition), TinkUtils.generateKeyId()))
			.keyEncryptionKey(kek)
			.build();
	}

	@Override
	public EncryptedKeyset create(Keyset keyset) {
		Assert.isInstanceOf(TinkKeyset.class, keyset,
				"This keyset factory only supports Tink keysets," + "you have passed: " + keyset.getClass());

		final KeyEncryptionKey kek = keyset.getKeyEncryptionKey();
		final List<EncryptedKey> keys = new ArrayList<>(keyset.getKeys().size());

		for (Key key : keyset.getKeys()) {
			final WrappedKeyMaterial encrypted;

			try {
				final ProtoKeySerialization serialization = MutableSerializationRegistry.globalInstance()
					.serializeKey(((TinkKey) key).getValue(), InsecureSecretKeyAccess.get());

				final KeyData data = KeyData.newBuilder()
					.setTypeUrl(serialization.getTypeUrl())
					.setKeyMaterialType(ProtoConversions.toProto(serialization.getKeyMaterialType()))
					.setValue(serialization.getValue())
					.build();

				encrypted = kek.wrap(new ByteArray(data.toByteArray()));
			} catch (Exception e) {
				throw new CryptoException.WrappingException(keyset.getName(), kek, e);
			}

			keys.add(EncryptedKey.from(key, encrypted));
		}

		return EncryptedKeyset.from(keyset, keys);
	}

	@Override
	public Keyset create(KeyEncryptionKey kek, EncryptedKeyset encryptedKeyset) throws IOException {
		final TinkKeyset.Builder builder = new TinkKeyset.Builder(encryptedKeyset)
			.keyEncryptionKey(kek);

		for (EncryptedKey encrypted : encryptedKeyset) {
			if (encrypted.data() == null) {
				continue;
			}

			final ByteArray unwrapped = kek.unwrap(encrypted.data());
			final KeyData data;

			try {
				data = KeyData.parseFrom(unwrapped.array());
			} catch (InvalidProtocolBufferException ex) {
				throw new CryptoException.UnwrappingException(encryptedKeyset.name(), kek, ex);
			}

			final com.google.crypto.tink.Key key;

			try {
				final ProtoKeySerialization serialization = ProtoKeySerialization.create(
					data.getTypeUrl(),
					data.getValue(),
					ProtoConversions.fromProto(data.getKeyMaterialType()),
					ProtoKeySerialization.OutputPrefixType.TINK,
					Integer.parseInt(encrypted.id())
				);

				key = MutableSerializationRegistry.globalInstance()
					.parseKey(serialization, InsecureSecretKeyAccess.get());
			} catch (Exception e) {
				throw new CryptoException.UnwrappingException(encryptedKeyset.name(), kek, e);
			}

			final TinkAlgorithm algorithm = (TinkAlgorithm) registry.resolve(encrypted.algorithm());

			builder.key(new TinkKey.Builder(key)
				.id(encrypted.id())
				.status(encrypted.status())
				.algorithm(algorithm)
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

}
