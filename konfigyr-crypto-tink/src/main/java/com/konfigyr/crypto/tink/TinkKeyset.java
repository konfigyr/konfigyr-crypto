package com.konfigyr.crypto.tink;

import com.google.crypto.tink.*;
import com.google.protobuf.InvalidProtocolBufferException;
import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import lombok.Builder;
import lombok.Value;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;

import java.security.GeneralSecurityException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import static com.konfigyr.crypto.CryptoException.KeysetOperationException;

/**
 * @author : Vladimir Spasic
 * @since : 21.08.23, Mon
 **/
@Value
@Builder
class TinkKeyset implements Keyset {

	@NonNull
	String name;

	@NonNull
	TinkAlgorithm algorithm;

	@NonNull
	KeyEncryptionKey keyEncryptionKey;

	@NonNull
	KeysetHandle handle;

	@NonNull
	Duration rotationInterval;

	@NonNull
	Instant nextRotationTime;

	@NonNull
	@Override
	public ByteArray encrypt(@NonNull ByteArray data, @Nullable ByteArray context) {
		assertSupportedOperation(KeysetOperation.ENCRYPT);

		final byte[] associatedData = context == null ? null : context.array();
		final byte[] encrypted;

		try {
			if (KeyType.OCTET == algorithm.type()) {
				encrypted = primitive(handle, Aead.class).encrypt(data.array(), associatedData);
			}
			else {
				encrypted = primitive(publicKeysetHandle(), HybridEncrypt.class).encrypt(data.array(), associatedData);
			}
		}
		catch (GeneralSecurityException e) {
			throw new KeysetOperationException(name, KeysetOperation.ENCRYPT, e);
		}

		return new ByteArray(encrypted);
	}

	@NonNull
	@Override
	public ByteArray decrypt(@NonNull ByteArray cipher, @Nullable ByteArray context) {
		assertSupportedOperation(KeysetOperation.DECRYPT);

		final byte[] associatedData = context == null ? null : context.array();
		final byte[] decrypted;

		try {
			if (KeyType.OCTET == algorithm.type()) {
				decrypted = primitive(handle, Aead.class).decrypt(cipher.array(), associatedData);
			}
			else {
				decrypted = primitive(handle, HybridDecrypt.class).decrypt(cipher.array(), associatedData);
			}
		}
		catch (GeneralSecurityException e) {
			throw new KeysetOperationException(name, KeysetOperation.DECRYPT, e);
		}

		return new ByteArray(decrypted);
	}

	@NonNull
	@Override
	public ByteArray sign(@NonNull ByteArray data) {
		assertSupportedOperation(KeysetOperation.SIGN);

		final byte[] signature;

		try {
			signature = primitive(handle, PublicKeySign.class).sign(data.array());
		}
		catch (GeneralSecurityException e) {
			throw new KeysetOperationException(name, KeysetOperation.SIGN, e);
		}

		return new ByteArray(signature);
	}

	@Override
	public boolean verify(@NonNull ByteArray signature, @NonNull ByteArray data) {
		assertSupportedOperation(KeysetOperation.VERIFY);

		try {
			primitive(publicKeysetHandle(), PublicKeyVerify.class).verify(signature.array(), data.array());
		}
		catch (GeneralSecurityException e) {
			return false;
		}

		return true;
	}

	@NonNull
	@Override
	public Keyset rotate() {
		final KeysetHandle handle;

		try {
			handle = KeysetManager.withKeysetHandle(this.handle).rotate(parseKeyTemplateProto()).getKeysetHandle();
		}
		catch (GeneralSecurityException e) {
			throw new CryptoException.KeysetException(name, "Failed to rotate keyset", e);
		}

		final Instant nextRotationTime = Instant.now().plus(rotationInterval);

		return TinkKeyset.builder()
			.name(name)
			.algorithm(algorithm)
			.keyEncryptionKey(keyEncryptionKey)
			.handle(handle)
			.rotationInterval(rotationInterval)
			.nextRotationTime(nextRotationTime)
			.build();
	}

	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		TinkKeyset that = (TinkKeyset) o;
		return name.equals(that.name) && algorithm.equals(that.algorithm)
				&& keyEncryptionKey.equals(that.keyEncryptionKey)
				&& handle.getKeysetInfo().equals(that.handle.getKeysetInfo())
				&& rotationInterval.equals(that.rotationInterval) && nextRotationTime.equals(that.nextRotationTime);
	}

	@Override
	public int hashCode() {
		return Objects.hash(name, algorithm, keyEncryptionKey, handle.getKeysetInfo(), rotationInterval,
				nextRotationTime);
	}

	@Override
	public String toString() {
		return "TinkKeyset[" + "name='" + name + '\'' + ", algorithm=" + algorithm + ", keyEncryptionKey="
				+ keyEncryptionKey + ", rotationInterval=" + rotationInterval + ", nextRotationTime=" + nextRotationTime
				+ ']';
	}

	private void assertSupportedOperation(KeysetOperation operation) {
		if (!algorithm.operations().contains(operation)) {
			throw new CryptoException.UnsupportedKeysetOperationException(name, operation, algorithm.operations());
		}
	}

	private KeysetHandle publicKeysetHandle() {
		try {
			return handle.getPublicKeysetHandle();
		}
		catch (GeneralSecurityException e) {
			throw new CryptoException.KeysetException(name, "Failed to load public key material", e);
		}
	}

	private <T> T primitive(KeysetHandle handle, Class<T> type) {
		final T primitive;

		try {
			primitive = handle.getPrimitive(type);
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

	private com.google.crypto.tink.proto.KeyTemplate parseKeyTemplateProto() throws GeneralSecurityException {
		final Parameters parameters = TinkUtils.keyTemplateForAlgorithm(algorithm).toParameters();

		try {
			return com.google.crypto.tink.proto.KeyTemplate.parseFrom(TinkProtoParametersFormat.serialize(parameters));
		}
		catch (InvalidProtocolBufferException e) {
			throw new IllegalStateException("Failed to parse Tink key template data", e);
		}
	}

}
