package com.konfigyr.io;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.core.io.InputStreamSource;
import org.springframework.core.io.buffer.DataBuffer;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Serial;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

/**
 * Immutable wrapper around a raw byte array.
 * <p>
 * All constructors and factory methods make a defensive copy of the supplied bytes, and
 * {@link #array()} returns a copy on every call, so callers can never observe or mutate
 * the internal state.
 *
 * <h2>Creating instances</h2>
 * <ul>
 *   <li>{@link #fromString(String)} / {@link #fromString(String, Charset)} — from a text string</li>
 *   <li>{@link #fromBase64String(String)} / {@link #fromBase64UrlString(String)} — decode Base64</li>
 *   <li>{@link #fromHexString(String)} — decode a lowercase hexadecimal string</li>
 *   <li>{@link #from(ByteBuffer)}, {@link #from(DataBuffer)}, {@link #from(byte[], int, int)} — from buffers and slices</li>
 *   <li>{@link #decode(String, Decoder)} — decode using a custom {@link Decoder}</li>
 * </ul>
 *
 * <h2>Encoding to strings</h2>
 * <ul>
 *   <li>{@link #encodeBase64()} / {@link #encodeBase64Url()} — standard and URL-safe Base64</li>
 *   <li>{@link #encodeHex()} — lowercase hexadecimal</li>
 *   <li>{@link #toString(Charset)} — decode bytes as a text string</li>
 *   <li>{@link #encode(Encoder)} — custom encoding via a {@link Encoder} lambda</li>
 * </ul>
 * <p>
 * When you need both directions (encode and decode), use a {@link ByteArrayCodec}, which
 * combines {@link Encoder} and {@link Decoder} into a single object. Built-in codecs are
 * available as constants on {@link ByteArrayCodec}: {@link ByteArrayCodec#BASE64},
 * {@link ByteArrayCodec#BASE64_URL_SAFE}, {@link ByteArrayCodec#BASE64_URL_SAFE_NO_PADDING},
 * and {@link ByteArrayCodec#HEX}. Custom codecs can be created with
 * {@link ByteArrayCodec#of(Encoder, Decoder)}.
 *
 * <h2>Manipulation</h2>
 * <ul>
 *   <li>{@link #slice(int, int)} — extract a sub-range as a new {@link ByteArray}</li>
 *   <li>{@link #concat(ByteArray)} — concatenate two arrays into a new {@link ByteArray}</li>
 * </ul>
 *
 * <h2>Security</h2>
 * <p>
 * Use {@link #constantTimeEquals(ByteArray)} rather than {@link #equals(Object)} when
 * comparing ciphertext, signatures, MAC values, or key material to prevent timing
 * side-channel attacks.
 *
 * @author Vladimir Spasic
 * @since 1.0.0
 * @see ByteArrayCodec
 **/
@NullMarked
public final class ByteArray implements InputStreamSource, Serializable {

	@Serial
	private static final long serialVersionUID = 3838515107166328896L;

	private static final ByteArray EMPTY = new ByteArray(new byte[0]);

	/**
	 * The underlying byte array that contains the actual data.
	 */
	private final byte[] array;

	/**
	 * Creates a new {@link ByteArray} by copying the data from the given array of bytes.
	 *
	 * @param array byte array data
	 */
	public ByteArray(byte[] array) {
		this(array, 0, array.length);
	}

	/**
	 * Creates a new {@link ByteArray} by copying the data from the given array of bytes.
	 *
	 * @param array byte array data
	 */
	private ByteArray(byte[] array, int offset, int length) {
		this.array = Arrays.copyOfRange(array, offset, offset + length);
	}

	/**
	 * Creates a new empty {@link ByteArray} instance.
	 *
	 * @return empty byte array, never {@literal null}
	 */
	public static ByteArray empty() {
		return EMPTY;
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given {@link ByteBuffer}.
	 *
	 * @param buffer byte buffer to be wrapped, can't be {@literal null}
	 * @return byte array, never {@literal null}
	 */
	public static ByteArray from(ByteBuffer buffer) {
		return new ByteArray(buffer.array());
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given {@link DataBuffer}.
	 *
	 * @param buffer data buffer to be wrapped, can't be {@literal null}
	 * @return byte array, never {@literal null}
	 */
	public static ByteArray from(DataBuffer buffer) {
		final ByteBuffer bb = ByteBuffer.allocate(buffer.capacity());
		buffer.toByteBuffer(bb);

		return new ByteArray(bb.array());
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given byte array over a slice of a Bytes.
	 *
	 * @param bytes bytes to be wrapped and sliced, can't be {@literal null}
	 * @param start the starting index of the slice
	 * @param length the length of the slice. If start + len is larger than the size of {@code bytes}, the
	 *               remaining data will be returned.
	 * @return byte array in the slice from {@code start} to {@code start + length}, never {@literal null}
	 */
	public static ByteArray from(byte[] bytes, int start, int length) {
		return new ByteArray(bytes, start, length);
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given string and the given {@link Decoder}.
	 *
	 * @param data raw string to be decoded and wrapped as a byte array, can't be {@literal null}
	 * @param decoder decoder to use for decoding the string, can't be {@literal null}
	 * @return byte array, never {@literal null}
	 */
	public static ByteArray decode(String data, Decoder decoder) {
		return new ByteArray(decoder.decode(data));
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given string. The string is converted to bytes using
	 * the {@link StandardCharsets#UTF_8} charset.
	 *
	 * @param data raw string to be wrapped, can't be {@literal null}
	 * @return byte array, never {@literal null}
	 */
	public static ByteArray fromString(String data) {
		return fromString(data, StandardCharsets.UTF_8);
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given string. The string is converted to bytes using
	 * the given {@link StandardCharsets} charset.
	 *
	 * @param data raw string to be wrapped, can't be {@literal null}
	 * @param charset character encoding used to encode the string, can't be {@literal null}
	 * @return byte array, never {@literal null}
	 */
	public static ByteArray fromString(String data, Charset charset) {
		return new ByteArray(data.getBytes(charset));
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given HEX encoded string.
	 *
	 * @return byte array, never {@literal null}
	 * @param data HEX encoded string to be wrapped, can't be {@literal null}
	 * @throws IllegalArgumentException when the HEX string is invalid
	 */
	public static ByteArray fromHexString(String data) {
		return decode(data, ByteArrayCodec.HEX);
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given Base64 encoded string.
	 *
	 * @return byte array, never {@literal null}
	 * @param data Base64 encoded string to be wrapped, can't be {@literal null}
	 * @throws IllegalArgumentException when the Base64 string is invalid
	 */
	public static ByteArray fromBase64String(String data) {
		return decode(data, ByteArrayCodec.BASE64);
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given Base64 URL safe encoded string.
	 *
	 * @return byte array, never {@literal null}
	 * @param data Base64 URL safe encoded string to be wrapped, can't be {@literal null}
	 * @throws IllegalArgumentException when the Base64 string is invalid
	 */
	public static ByteArray fromBase64UrlString(String data) {
		return decode(data, ByteArrayCodec.BASE64_URL_SAFE);
	}

	/**
	 * Returns a copy of the byte array contents.
	 *
	 * @return byte array contents.
	 */
	public byte[] array() {
		return Arrays.copyOf(array, array.length);
	}

	@Override
	public InputStream getInputStream() {
		return new ByteArrayInputStream(array());
	}

	/**
	 * Returns a new {@link ByteArray} containing the bytes from {@code start} (inclusive) up to
	 * {@code start + length}. If {@code start + length} exceeds the size of this array, the
	 * remaining bytes from {@code start} to the end are returned.
	 *
	 * @param start the start index of the slice, inclusive
	 * @param length the number of bytes to include in the slice
	 * @return sliced byte array, never {@literal null}
	 */
	public ByteArray slice(int start, int length) {
		return new ByteArray(array, start, length);
	}

	/**
	 * Returns a new {@link ByteArray} whose contents are the bytes of this array followed
	 * immediately by the bytes of {@code other}.
	 *
	 * @param other the byte array to append, can't be {@literal null}
	 * @return concatenated byte array, never {@literal null}
	 */
	public ByteArray concat(ByteArray other) {
		if (isEmpty()) {
			return other;
		}
		if (other.isEmpty()) {
			return this;
		}
		final byte[] result = Arrays.copyOf(array, size() + other.size());
		System.arraycopy(other.array, 0, result, size(), other.size());
		return new ByteArray(result);
	}

	/**
	 * Encodes the contents of this byte array into a HEX string.
	 *
	 * @return HEX encoded string, never {@literal null}.
	 */
	public String encodeHex() {
		return encode(ByteArrayCodec.HEX);
	}

	/**
	 * Encodes the contents of this byte array into a Base64 string.
	 *
	 * @return Base64 encoded string, never {@literal null}.
	 */
	public String encodeBase64() {
		return encode(ByteArrayCodec.BASE64);
	}

	/**
	 * Encodes the contents of this byte array into a Base64 URL Safe string.
	 *
	 * @return Base64 URL encoded string, never {@literal null}.
	 */
	public String encodeBase64Url() {
		return encode(ByteArrayCodec.BASE64_URL_SAFE);
	}

	/**
	 * Decodes the contents of this byte array into a string using the given {@link Charset}.
	 * This is the inverse of {@link #fromString(String, Charset)}.
	 *
	 * @param charset character encoding used to decode the bytes, can't be {@literal null}
	 * @return decoded string, never {@literal null}
	 */
	public String toString(Charset charset) {
		return new String(array, charset);
	}

	/**
	 * Encodes the contents of this byte array using the given encoder.
	 *
	 * @param encoder encoder to use for encoding the byte array, can't be {@literal null}.
	 * @return encoded string, never {@literal null}.
	 */
	public String encode(Encoder encoder) {
		return encoder.encode(array);
	}

	/**
	 * Checks if the underlying byte array contents are empty. This is performed by checking the size
	 * of the contents.
	 *
	 * @return {@code true} if the array is empty, {@code false} otherwise.
	 */
	public boolean isEmpty() {
		return array.length == 0;
	}

	/**
	 * Returns the size of the underlying byte array.
	 *
	 * @return byte array size, {@literal 0} if empty.
	 */
	public int size() {
		return array.length;
	}

	/**
	 * Compares this {@link ByteArray} to another in constant time using {@link MessageDigest#isEqual(byte[], byte[])}.
	 * <p>
	 * Use this method, rather than {@link #equals(Object)}, whenever comparing ciphertext, signatures,
	 * MAC values, or key material, to prevent timing side-channel attacks.
	 *
	 * @param other the byte array to compare against, may be {@literal null}
	 * @return {@code true} if both arrays have identical contents, {@code false} otherwise
	 */
	public boolean constantTimeEquals(byte @Nullable [] other) {
		return other != null && MessageDigest.isEqual(this.array, other);
	}

	/**
	 * Compares this {@link ByteArray} to another in constant time using {@link MessageDigest#isEqual(byte[], byte[])}.
	 * <p>
	 * Use this method, rather than {@link #equals(Object)}, whenever comparing ciphertext, signatures,
	 * MAC values, or key material, to prevent timing side-channel attacks.
	 *
	 * @param other the byte array to compare against, may be {@literal null}
	 * @return {@code true} if both arrays have identical contents, {@code false} otherwise
	 */
	public boolean constantTimeEquals(@Nullable ByteArray other) {
		return constantTimeEquals(other == null ? null : other.array);
	}

	/**
	 * {@inheritDoc}
	 * <p>
	 * <strong>Security note:</strong> this method uses {@link Arrays#equals(byte[], byte[])} which is
	 * <em>not</em> constant-time. Never use it to compare ciphertext, signatures, MAC values, or key
	 * material. Use {@link #constantTimeEquals(ByteArray)} instead.
	 */
	@Override
	public boolean equals(Object o) {
		if (this == o)
			return true;
		if (o == null || getClass() != o.getClass())
			return false;
		ByteArray byteArray = (ByteArray) o;
		return Arrays.equals(array, byteArray.array);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(array);
	}

	@Override
	public String toString() {
		return "ByteArray[" + size() + "]";
	}

	/**
	 * Interface used to encode the byte array into a string.
	 */
	@FunctionalInterface
	public interface Encoder {

		/**
		 * Encodes the given byte array into a string.
		 *
		 * @param bytes the bytes to encode, can't be {@literal null}
		 * @return the encoded string, never {@literal null}
		 */
		String encode(byte[] bytes);

	}

	/**
	 * Interface used to decode the string into a byte array.
	 */
	@FunctionalInterface
	public interface Decoder {

		/**
		 * Decodes the given string into a byte array.
		 *
		 * @param string the string to decode, can't be {@literal null}
		 * @return the decoded byte array, never {@literal null}
		 */
		byte[] decode(String string);

	}
}
