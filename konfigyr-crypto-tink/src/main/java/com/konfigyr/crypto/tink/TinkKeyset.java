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
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
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
		assertSupportedOperation(KeysetOperation.ENCRYPT);

		final byte[] associatedData = context == null ? null : context.array();
		final byte[] encrypted;

		try {
			final TinkKey key = getPrimary();

			if (KeyType.OCTET == key.getType()) {
				encrypted = primitive(key, Aead.class)
					.encrypt(data.array(), associatedData);
			} else {
				encrypted = primitive(key, HybridEncrypt.class)
					.encrypt(data.array(), associatedData);
			}
		} catch (GeneralSecurityException e) {
			throw new KeysetOperationException(name, KeysetOperation.ENCRYPT, e);
		}

		return new ByteArray(encrypted);
	}

	@Override
	public ByteArray decrypt(ByteArray cipher, @Nullable ByteArray context) {
		assertSupportedOperation(KeysetOperation.DECRYPT);

		final byte[] associatedData = context == null ? null : context.array();
		GeneralSecurityException lastException = null;

		for (TinkKey key : prefixMap.getAllWithMatchingPrefix(cipher.array())) {
			try {
				final byte[] decrypted;

				if (KeyType.OCTET == key.getType()) {
					decrypted = primitive(key, Aead.class).decrypt(cipher.array(), associatedData);
				} else {
					decrypted = primitive(key, HybridDecrypt.class).decrypt(cipher.array(), associatedData);
				}

				return new ByteArray(decrypted);
			} catch (GeneralSecurityException e) {
				lastException = e;
			}
		}

		if (lastException != null) {
			throw new KeysetOperationException(name, KeysetOperation.DECRYPT, lastException);
		}

		throw new KeysetOperationException(name, KeysetOperation.DECRYPT, "Failed to decrypt cipher");
	}

	@Override
	public ByteArray sign(ByteArray data) {
		assertSupportedOperation(KeysetOperation.SIGN);

		final byte[] signature;

		try {
			final TinkKey key = getPrimary();

			signature = primitive(key, PublicKeySign.class).sign(data.array());
		} catch (GeneralSecurityException e) {
			throw new KeysetOperationException(name, KeysetOperation.SIGN, e);
		}

		return new ByteArray(signature);
	}

	@Override
	public boolean verify(ByteArray signature, ByteArray data) {
		assertSupportedOperation(KeysetOperation.VERIFY);

		for (TinkKey key : prefixMap.getAllWithMatchingPrefix(signature.array())) {
			try {
				primitive(key, PublicKeyVerify.class).verify(signature.array(), data.array());
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
