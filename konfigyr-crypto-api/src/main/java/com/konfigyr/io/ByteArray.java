package com.konfigyr.io;

import org.springframework.core.io.InputStreamSource;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.lang.NonNull;

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
 * making a copy upon initialization, and also makes a copy if the underlying bytes are
 * read.
 * <p>
 * This class also provides a way to encode the byte array into a plain or Base64 encoded
 * string.
 *
 * @author : Vladimir Spasic
 * @since : 01.09.22, Thu
 **/
public record ByteArray(byte[] array) implements InputStreamSource, Serializable {

	@Serial
	private static final long serialVersionUID = 3838515107166328896L;

	private static final ByteArray EMPTY = new ByteArray(new byte[0]);

	/**
	 * Creates a new {@link ByteArray} by copying the data from the given array of bytes.
	 * @param array byte array data
	 */
	public ByteArray(byte[] array) {
		this.array = Arrays.copyOf(array, array.length);
	}

	/**
	 * Creates a new empty {@link ByteArray} instance.
	 * @return empty byte array, never {@literal null}
	 */
	@NonNull
	public static ByteArray empty() {
		return EMPTY;
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given {@link ByteBuffer}.
	 * @param buffer byte buffer to be wrapped, can't be {@literal null}
	 * @return byte array, never {@literal null}
	 */
	@NonNull
	public static ByteArray from(@NonNull ByteBuffer buffer) {
		return new ByteArray(buffer.array());
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given {@link DataBuffer}.
	 * @param buffer data buffer to be wrapped, can't be {@literal null}
	 * @return byte array, never {@literal null}
	 */
	@NonNull
	public static ByteArray from(@NonNull DataBuffer buffer) {
		final ByteBuffer bb = ByteBuffer.allocate(buffer.capacity());
		buffer.toByteBuffer(bb);

		return new ByteArray(bb.array());
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given string. The string is
	 * converted to bytes using the {@link StandardCharsets#UTF_8} charset.
	 * @param data raw string to be wrapped, can't be {@literal null}
	 * @return byte array, never {@literal null}
	 */
	@NonNull
	public static ByteArray fromString(@NonNull String data) {
		return fromString(data, StandardCharsets.UTF_8);
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given string. The string is
	 * converted to bytes using the given {@link StandardCharsets} charset.
	 * @param data raw string to be wrapped, can't be {@literal null}
	 * @param charset character encoding used to encode the string, can't be
	 * {@literal null}
	 * @return byte array, never {@literal null}
	 */
	@NonNull
	public static ByteArray fromString(@NonNull String data, @NonNull Charset charset) {
		return new ByteArray(data.getBytes(charset));
	}

	/**
	 * Creates a new {@link ByteArray} instance from the given Base64 URL Safe encoded
	 * string.
	 * @return byte array, never {@literal null}
	 * @param data Base64 encoded string to be wrapped, can't be {@literal null}
	 * @throws IllegalArgumentException when the Base64 string is invalid
	 */
	@NonNull
	public static ByteArray fromBase64String(String data) {
		return new ByteArray(Base64.getUrlDecoder().decode(data));
	}

	/**
	 * Returns a copy of the byte array contents.
	 * @return byte array contents.
	 */
	public byte[] array() {
		return Arrays.copyOf(array, array.length);
	}

	@NonNull
	@Override
	public InputStream getInputStream() {
		return new ByteArrayInputStream(array());
	}

	/**
	 * Encodes the contents of this byte array into a Base64 URL Safe string.
	 * @return Base64 URL encoded string, never {@literal null}.
	 */
	public String encode() {
		return Base64.getUrlEncoder().encodeToString(array);
	}

	/**
	 * Checks if the underlying byte array contents are empty. This is performed by
	 * checking the size of the contents.
	 * @return is the array empty
	 */
	public boolean isEmpty() {
		return array == null || array.length == 0;
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
}
