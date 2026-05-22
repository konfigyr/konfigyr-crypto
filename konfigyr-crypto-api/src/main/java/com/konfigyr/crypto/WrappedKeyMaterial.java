package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.core.io.InputStreamSource;
import org.springframework.util.Assert;

import java.io.InputStream;

/**
 * Immutable container for key material that has been wrapped (encrypted) by a
 * {@link KeyEncryptionKey}. This type is the sole output of {@link KeyEncryptionKey#wrap}
 * and the required input to {@link KeyEncryptionKey#unwrap}, making it impossible at the
 * type level to pass raw plaintext bytes where wrapped material is expected, or to pass
 * wrapped material where plaintext is expected.
 * <p>
 * Instances are intentionally not {@link java.io.Serializable}. Serializing wrapped key
 * material to a remote store without an explicit, audited transport-security decision is a
 * key-management risk. Callers that need persistence (e.g., a {@link KeysetRepository})
 * must extract the underlying bytes via {@link #toByteArray()} and handle storage
 * explicitly.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see KeyEncryptionKey
 * @see EncryptedKey
 */
@NullMarked
public final class WrappedKeyMaterial implements InputStreamSource {

	private final ByteArray bytes;

	private WrappedKeyMaterial(ByteArray bytes) {
		this.bytes = bytes;
	}

	/**
	 * Creates a new {@link WrappedKeyMaterial} from the given {@link ByteArray}.
	 *
	 * @param bytes the wrapped key bytes, can't be {@literal null}
	 * @return a new {@link WrappedKeyMaterial} instance, never {@literal null}
	 */
	public static WrappedKeyMaterial of(ByteArray bytes) {
		Assert.notNull(bytes, "Wrapped key material bytes can't be null");
		Assert.isTrue(!bytes.isEmpty(), "Wrapped key material bytes can't be empty");
		return new WrappedKeyMaterial(bytes);
	}

	/**
	 * Creates a new {@link WrappedKeyMaterial} from the given raw byte array.
	 *
	 * @param bytes the wrapped key bytes, can't be {@literal null}
	 * @return a new {@link WrappedKeyMaterial} instance, never {@literal null}
	 */
	public static WrappedKeyMaterial of(byte[] bytes) {
		return of(new ByteArray(bytes));
	}

	/**
	 * Creates a new {@link WrappedKeyMaterial} from the given UTF-8 encoded string,
	 * using {@link ByteArray#fromString(String)} for encoding.
	 *
	 * @param value the string to encode as wrapped key material, can't be {@literal null}
	 * @return a new {@link WrappedKeyMaterial} instance, never {@literal null}
	 */
	public static WrappedKeyMaterial of(String value) {
		return of(ByteArray.fromString(value));
	}

	/**
	 * Returns the wrapped key bytes as a primitive byte array.
	 * <p>
	 * The returned value is intended for persistence (e.g., writing to a
	 * {@link KeysetRepository}) or for passing back into {@link KeyEncryptionKey#unwrap}.
	 * It must never be treated as or passed along as plaintext key material.
	 *
	 * @return the wrapped key bytes, never {@literal null}
	 */
	public byte[] toByteArray() {
		return bytes.array();
	}

	@Override
	public InputStream getInputStream() {
		return bytes.getInputStream();
	}

	@Override
	public boolean equals(@Nullable Object obj) {
		if (this == obj) return true;
		if (!(obj instanceof WrappedKeyMaterial other)) return false;
		return bytes.equals(other.bytes);
	}

	@Override
	public int hashCode() {
		return bytes.hashCode();
	}

	@Override
	public String toString() {
		return "WrappedKeyMaterial[" + bytes.size() + " bytes]";
	}

}
