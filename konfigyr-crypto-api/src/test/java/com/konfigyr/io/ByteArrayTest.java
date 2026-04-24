package com.konfigyr.io;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author : Vladimir Spasic
 * @since : 01.09.22, Thu
 **/
class ByteArrayTest {

	private final static String TEST_ORIGINAL = "testing string";

	@Test
	@DisplayName("should create immutable byte array instances by copying the data from the original byte array")
	void shouldCreateImmutableByteArrays() {
		var data = TEST_ORIGINAL.getBytes();

		final var array = new ByteArray(data);
		assertThat(data).isEqualTo(array.array());

		data[0] = 6;
		assertThat(data).isNotEqualTo(array.array());

		data = array.array();
		data[0] = 8;
		assertThat(data).isNotEqualTo(array.array());
	}

	@Test
	@DisplayName("should create immutable byte array instances by copying the data slice")
	void shouldCreateImmutableByteArraySlices() {
		var data = new byte[] { 1, 2, 3, 4, 5, 6 };

		final var array = ByteArray.from(data, 2, 2);
		assertThat(array.array()).isEqualTo(new byte[] { 3, 4 });

		data[3] = 6;
		assertThat(array.array()).isEqualTo(new byte[] { 3, 4 });

		data = array.array();
		data[1] = 8;
		assertThat(array.array()).isNotEqualTo(data);
	}

	@Test
	@DisplayName("should create a byte array using the Base64 decoder function and test encoding")
	void shouldDecodeAndEncodeBase64() {
		final var data = "c3ViamVjdHM/ID4gMTA=";
		final var array = ByteArray.decode(data, ByteArray.BASE_64_DECODER);

		assertThat(array)
			.isNotNull()
			.isEqualTo(ByteArray.fromBase64String(data));

		assertThat(array.encodeBase64())
			.isEqualTo(array.encode(ByteArray.BASE_64_ENCODER))
			.isEqualTo(data);

		assertThat(array.encodeBase64Url())
			.isNotEqualTo(array.encode(ByteArray.BASE_64_ENCODER))
			.isNotEqualTo(data);
	}

	@Test
	@DisplayName("should create a byte array using the Base64 URL safe decoder function and test encoding")
	void shouldDecodeAndEncodeBase64UrlSafe() {
		final var data = "c3ViamVjdHM_ID4gMTA=";
		final var array = ByteArray.decode(data, ByteArray.BASE_64_URL_SAFE_DECODER);

		assertThat(array)
			.isNotNull()
			.isEqualTo(ByteArray.fromBase64UrlString(data));

		assertThat(array.encodeBase64Url())
			.isEqualTo(array.encode(ByteArray.BASE_64_URL_SAFE_ENCODER))
			.isEqualTo(data);

		assertThat(array.encodeBase64())
			.isNotEqualTo(array.encode(ByteArray.BASE_64_URL_SAFE_ENCODER))
			.isNotEqualTo(data);
	}

	@Test
	@DisplayName("should create an input stream from data stored in the byte array")
	void shouldCreateInputStream() {
		final var array = ByteArray.fromString(TEST_ORIGINAL);

		assertThat(array)
			.isNotNull()
			.extracting(ByteArray::getInputStream)
			.isNotNull()
			.isInstanceOf(ByteArrayInputStream.class)
			.asInstanceOf(InstanceOfAssertFactories.type(ByteArrayInputStream.class))
			.extracting(is -> new String(is.readAllBytes()))
			.isEqualTo(TEST_ORIGINAL);
	}

	@Test
	@DisplayName("should create a byte array from a byte buffer")
	void shouldCreateByteArrayFromByteBuffer() {
		final var data = ByteBuffer.wrap(TEST_ORIGINAL.getBytes(StandardCharsets.UTF_8));
		final var array = ByteArray.from(data);

		assertThat(array)
			.isNotNull()
			.returns(data.array(), ByteArray::array)
			.returns(false, ByteArray::isEmpty)
			.returns(14, ByteArray::size)
			.returns(TEST_ORIGINAL, it -> array.encode(String::new));
	}

	@Test
	@DisplayName("should create a byte array from a data buffer")
	void shouldCreateByteArrayFromDataBuffer() {
		final var data = DefaultDataBufferFactory.sharedInstance
			.wrap(TEST_ORIGINAL.getBytes(StandardCharsets.UTF_8));

		final var array = ByteArray.from(data);

		assertThat(array)
			.isNotNull()
			.returns(data.getNativeBuffer().array(), ByteArray::array)
			.returns(false, ByteArray::isEmpty)
			.returns(14, ByteArray::size)
			.returns(TEST_ORIGINAL, it -> array.encode(String::new));
	}

	@Test
	@DisplayName("should create a byte array from a string and default charset")
	void shouldCreateByteArrayFromString() {
		final var array = ByteArray.fromString(TEST_ORIGINAL);

		assertThat(array)
			.isNotNull()
			.returns(TEST_ORIGINAL.getBytes(), ByteArray::array)
			.returns(false, ByteArray::isEmpty)
			.returns(14, ByteArray::size)
			.returns(TEST_ORIGINAL, it -> array.encode(String::new));
	}

	@Test
	@DisplayName("should create a byte array from a string and specified charset")
	void shouldCreateByteArrayFromStringAndSpecifiedCharset() {
		final var array = ByteArray.fromString(TEST_ORIGINAL, StandardCharsets.UTF_16);

		assertThat(array)
			.isNotNull()
			.returns(TEST_ORIGINAL.getBytes(StandardCharsets.UTF_16), ByteArray::array)
			.returns(false, ByteArray::isEmpty)
			.returns(30, ByteArray::size)
			.returns(TEST_ORIGINAL, it -> array.encode(data -> new String(data, StandardCharsets.UTF_16)));
	}

	@Test
	@DisplayName("should create empty byte arrays and reuse the empty byte array singleton")
	void emptyByteArraysShouldBeEqual() {
		final var empty = ByteArray.empty();

		assertThat(empty)
			.isNotNull()
			.isEqualTo(ByteArray.empty())
			.isSameAs(ByteArray.empty())
			.hasToString("ByteArray[0]")
			.returns(true, ByteArray::isEmpty)
			.returns(0, ByteArray::size)
			.returns(new byte[0], ByteArray::array)
			.returns("", it -> it.encode(String::new))
			.returns("", it -> new String(it.array()));
	}

	@Test
	@DisplayName("should display just the size in the string representation")
	void stringRepresentationShouldDisplaySize() {
		assertThat(ByteArray.fromString(TEST_ORIGINAL))
			.hasToString("ByteArray[14]");
	}

	@Test
	@DisplayName("should perform identity and equality checks based on the contents")
	void shouldCheckEquality() {
		final var foo = ByteArray.fromString("foo array");
		final var bar = ByteArray.fromString("bar array");

		assertThat(foo)
			.isEqualTo(ByteArray.fromString("foo array"))
			.hasSameHashCodeAs(ByteArray.fromString("foo array"))
			.isNotEqualTo(bar)
			.doesNotHaveSameHashCodeAs(bar);
	}

}
