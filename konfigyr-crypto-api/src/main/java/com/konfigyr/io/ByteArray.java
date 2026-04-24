package com.konfigyr.io;

import org.jspecify.annotations.NullMarked;
import org.springframework.core.io.InputStreamSource;
import org.springframework.core.io.buffer.DataBuffer;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.Serial;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Base64;

/**
 * Utility class that serves as an immutable wrapper around a byte array.
 * <p>
 * Wraps a bytearray, so it prevents callers from modifying its contents. It does this by
 * making a copy upon initialization and also makes a copy if the underlying bytes are
 * read.
 * <p>
 * This class also provides a way to encode the byte array into a plain or Base64 encoded
 * string.
 *
 * @author : Vladimir Spasic
 * @since : 01.09.22, Thu
 **/
@NullMarked
public final class ByteArray implements InputStreamSource, Serializable {

	@Serial
	private static final long serialVersionUID = 3838515107166328896L;

	private static final ByteArray EMPTY = new ByteArray(new byte[0]);

	/**
	 * The implementation of the {@link Encoder} that uses {@link Base64.Encoder} to encode the byte array.
	 */
	static final Encoder BASE_64_ENCODER = Base64.getEncoder()::encodeToString;

	/**
	 * The implementation of the {@link Decoder} that uses {@link Base64.Decoder} to decode the byte array.
	 */
	static final Decoder BASE_64_DECODER = Base64.getDecoder()::decode;

	/**
	 * The implementation of the {@link Encoder} that uses URL Safe variant of the {@link Base64.Encoder} to
	 * encode the value to a byte array.
	 */
	static final Encoder BASE_64_URL_SAFE_ENCODER = Base64.getUrlEncoder()::encodeToString;

	/**
	 * The implementation of the {@link Decoder} that uses URL Safe variant of the {@link Base64.Decoder} to
	 * decode the value to a byte array.
	 */
	static final Decoder BASE_64_URL_SAFE_DECODER = Base64.getUrlDecoder()::decode;

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
	 * Creates a new {@link ByteArray} instance from the given Base64 encoded string.
	 *
	 * @return byte array, never {@literal null}
	 * @param data Base64 encoded string to be wrapped, can't be {@literal null}
	 * @throws IllegalArgumentException when the Base64 string is invalid
	 */
	public static ByteArray fromBase64String(String data) {
		return decode(data, BASE_64_DECODER);
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given Base64 URL safe encoded string.
	 *
	 * @return byte array, never {@literal null}
	 * @param data Base64 URL safe encoded string to be wrapped, can't be {@literal null}
	 * @throws IllegalArgumentException when the Base64 string is invalid
	 */
	public static ByteArray fromBase64UrlString(String data) {
		return decode(data, BASE_64_URL_SAFE_DECODER);
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
	 * Encodes the contents of this byte array into a Base64 string.
	 *
	 * @return Base64 encoded string, never {@literal null}.
	 */
	public String encodeBase64() {
		return encode(BASE_64_ENCODER);
	}

	/**
	 * Encodes the contents of this byte array into a Base64 URL Safe string.
	 *
	 * @return Base64 URL encoded string, never {@literal null}.
	 */
	public String encodeBase64Url() {
		return encode(BASE_64_URL_SAFE_ENCODER);
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
	 * @return byte array size, {@literal 0} if empty.
	 */
	public int size() {
		return array.length;
	}

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
