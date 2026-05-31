package com.konfigyr.crypto.tink;

import com.google.crypto.tink.*;
import com.google.crypto.tink.Key;
import com.google.crypto.tink.internal.MutablePrimitiveRegistry;
import com.google.crypto.tink.internal.PrefixMap;
import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.security.GeneralSecurityException;

import static com.konfigyr.crypto.CryptoException.KeysetOperationException;

/**
 * Implementation of the {@link Keyset} that uses the Tink {@link KeysetHandle} to perform
 * cryptographic operations.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 **/
@NullMarked
class TinkKeyset extends AbstractKeyset<TinkKey> {

	PrefixMap<TinkKey> prefixMap;

	private TinkKeyset(Builder builder) {
		super(builder);

		PrefixMap.Builder<TinkKey> prefixMap = new PrefixMap.Builder<>();

		for (TinkKey key : keys) {
			try {
				prefixMap.put(TinkUtils.extractKeyOutputPrefix(key.getValue()), key);
			} catch (GeneralSecurityException ex) {
				throw new IllegalArgumentException("Failed to register Tink key: " + key, ex);
			}
		}

		this.prefixMap = prefixMap.build();
	}

	@Override
	public ByteArray encrypt(ByteArray data, @Nullable ByteArray context) {
		Assert.isTrue(!data.isEmpty(), "Cannot encrypt an empty byte array");
		assertSupportedOperation(KeysetOperation.ENCRYPT);

		final TinkKey key = requireActivePrimary();

		return data.transform(bytes -> {
			final byte[] associatedData = context == null ? null : context.array();

			try {
				if (KeyType.OCTET == key.getType()) {
					return primitive(key, Aead.class).encrypt(bytes, associatedData);
				} else {
					return primitive(key, HybridEncrypt.class).encrypt(bytes, associatedData);
				}
			} catch (GeneralSecurityException e) {
				throw new KeysetOperationException(name, KeysetOperation.ENCRYPT, e);
			}
		});
	}

	@Override
	public ByteArray decrypt(ByteArray cipher, @Nullable ByteArray context) {
		Assert.isTrue(!cipher.isEmpty(), "Cannot decrypt an empty byte array");
		assertSupportedOperation(KeysetOperation.DECRYPT);

		return cipher.transform(bytes -> {
			final byte[] associatedData = context == null ? null : context.array();
			GeneralSecurityException lastException = null;

			for (TinkKey key : prefixMap.getAllWithMatchingPrefix(bytes)) {
				try {
					if (KeyType.OCTET == key.getType()) {
						return primitive(key, Aead.class).decrypt(bytes, associatedData);
					} else {
						return primitive(key, HybridDecrypt.class).decrypt(bytes, associatedData);
					}
				} catch (GeneralSecurityException e) {
					lastException = e;
				}
			}

			if (lastException != null) {
				throw new KeysetOperationException(name, KeysetOperation.DECRYPT, lastException);
			}

			throw new KeysetOperationException(name, KeysetOperation.DECRYPT, "Failed to decrypt cipher");
		});
	}

	@Override
	public ByteArray sign(ByteArray data) {
		Assert.isTrue(!data.isEmpty(), "Cannot sign an empty byte array");
		assertSupportedOperation(KeysetOperation.SIGN);

		final TinkKey key = requireActivePrimary();

		return data.transform(bytes -> {
			try {
				return primitive(key, PublicKeySign.class).sign(bytes);
			} catch (GeneralSecurityException e) {
				throw new KeysetOperationException(name, KeysetOperation.SIGN, e);
			}
		});
	}

	@Override
	public boolean verify(ByteArray signature, ByteArray data) {
		Assert.isTrue(!signature.isEmpty(), "Cannot verify an empty signature");
		Assert.isTrue(!data.isEmpty(), "Cannot verify a signature against an empty byte array");
		assertSupportedOperation(KeysetOperation.VERIFY);

		// create only one byte array to avoid copying the data multiple times
		final byte[] bytes = signature.array();

		for (TinkKey key : prefixMap.getAllWithMatchingPrefix(bytes)) {
			try {
				primitive(key, PublicKeyVerify.class).verify(bytes, data.array());
				return true;
			} catch (GeneralSecurityException e) {
				// try the next key in the chain...
			}
		}

		return false;
	}

	@Override
	protected String generateId() {
		return TinkUtils.generateKeyId();
	}

	@Override
	protected Keyset doRotate(KeyDefinition definition, String uniqueId) {
		final TinkKeyset.Builder builder = new TinkKeyset.Builder(this)
			.key(TinkKey.generate(definition, uniqueId));

		stream().map(TinkKey.class::cast).forEach(existing -> {
			if (existing.isPrimary() && definition.isPrimary()) {
				builder.key(new TinkKey.Builder(existing).primary(false).build());
			} else {
				builder.key(existing);
			}
		});

		return builder.build();
	}

	private void assertSupportedOperation(KeysetOperation operation) {
		if (!purpose.operations().contains(operation)) {
			throw new CryptoException.UnsupportedKeysetOperationException(name, operation, purpose.operations());
		}
	}

	private <T> T primitive(TinkKey key, Class<T> type) {
		final T primitive;

		try {
			final Key cryptographicKey;

			if (ClassUtils.isAssignable(PublicKeyVerify.class, type)) {
				cryptographicKey = TinkUtils.extractPublicKey(key.getValue());
			} else if (ClassUtils.isAssignable(HybridEncrypt.class, type)) {
				cryptographicKey = TinkUtils.extractPublicKey(key.getValue());
			} else {
				cryptographicKey = key.getValue();
			}

			primitive = MutablePrimitiveRegistry.globalInstance().getPrimitive(cryptographicKey, type);
		}
		catch (GeneralSecurityException e) {
			throw new CryptoException.KeysetException(name,
					"Failed to load primitive with type '" + ClassUtils.getQualifiedName(type) + "' for key '" + name
							+ "'. Please make sure that " + "the algorithm is properly set for this keyset.",
					e);
		}

		Assert.notNull(primitive, "Tink Keyset Primitive can not be null for keyset: " + name);

		return primitive;
	}

	static final class Builder extends AbstractKeyset.Builder<TinkKey, TinkKeyset, Builder> {

		Builder(KeysetDefinition definition) {
			super(definition);
		}

		Builder(TinkKeyset keyset) {
			super(keyset);
		}

		Builder(EncryptedKeyset keyset) {
			super(keyset);
		}

		@Override
		public TinkKeyset build() {
			return new TinkKeyset(this);
		}
	}

}
