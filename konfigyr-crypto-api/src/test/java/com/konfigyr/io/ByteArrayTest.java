package com.konfigyr.io;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.Test;
import org.springframework.core.io.buffer.DefaultDataBufferFactory;

import java.io.ByteArrayInputStream;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author : vladimir.spasic.86@gmail.com
 * @since : 01.09.22, Thu
 **/
class ByteArrayTest {

	private final static String TEST_ORIGINAL = "testing string";

	private final static String TEST_ENCODED = "dGVzdGluZyBiYXNlNjQ=";

	@Test
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
	void shouldCreateInputStream() {
		final var array = ByteArray.fromString(TEST_ORIGINAL);

		assertThat(array).isNotNull()
			.extracting("inputStream")
			.isNotNull()
			.isInstanceOf(ByteArrayInputStream.class)
			.asInstanceOf(InstanceOfAssertFactories.type(ByteArrayInputStream.class))
			.extracting(is -> new String(is.readAllBytes()))
			.isEqualTo(TEST_ORIGINAL);
	}

	@Test
	void shouldCreateByteArrayFromByteBuffer() {
		final var array = ByteArray.from(ByteBuffer.wrap(TEST_ORIGINAL.getBytes(StandardCharsets.UTF_8)));

		assertThat(array).isNotNull()
			.isEqualTo(ByteArray.fromString(TEST_ORIGINAL))
			.isEqualTo(ByteArray.fromBase64String("dGVzdGluZyBzdHJpbmc="))
			.isNotEqualTo(ByteArray.fromString(TEST_ORIGINAL, StandardCharsets.UTF_16))
			.returns(false, ByteArray::isEmpty)
			.returns(14, ByteArray::size)
			.returns("dGVzdGluZyBzdHJpbmc=", ByteArray::encode)
			.returns(TEST_ORIGINAL, it -> new String(it.array()))
			.extracting(ByteArray::array)
			.isEqualTo(array.array());
	}

	@Test
	void shouldCreateByteArrayFromDataBuffer() {
		final var array = ByteArray
			.from(DefaultDataBufferFactory.sharedInstance.wrap(TEST_ORIGINAL.getBytes(StandardCharsets.UTF_8)));

		assertThat(array).isNotNull()
			.isEqualTo(ByteArray.fromString(TEST_ORIGINAL))
			.isEqualTo(ByteArray.fromBase64String("dGVzdGluZyBzdHJpbmc="))
			.isNotEqualTo(ByteArray.fromString(TEST_ORIGINAL, StandardCharsets.UTF_16))
			.returns(false, ByteArray::isEmpty)
			.returns(14, ByteArray::size)
			.returns("dGVzdGluZyBzdHJpbmc=", ByteArray::encode)
			.returns(TEST_ORIGINAL, it -> new String(it.array()))
			.extracting(ByteArray::array)
			.isEqualTo(array.array());
	}

	@Test
	void shouldCreateByteArrayFromString() {
		final var array = ByteArray.fromString(TEST_ORIGINAL);

		assertThat(array).isNotNull()
			.isEqualTo(ByteArray.fromString(TEST_ORIGINAL))
			.isEqualTo(ByteArray.fromBase64String("dGVzdGluZyBzdHJpbmc="))
			.isNotEqualTo(ByteArray.fromString(TEST_ORIGINAL, StandardCharsets.UTF_16))
			.returns(false, ByteArray::isEmpty)
			.returns(14, ByteArray::size)
			.returns("dGVzdGluZyBzdHJpbmc=", ByteArray::encode)
			.returns(TEST_ORIGINAL, it -> new String(it.array()))
			.extracting(ByteArray::array)
			.isEqualTo(array.array());
	}

	@Test
	void shouldCreateByteArrayFromStringAndSpecifiedCharset() {
		final var array = ByteArray.fromString(TEST_ORIGINAL, StandardCharsets.UTF_16);

		assertThat(array).isNotNull()
			.isEqualTo(ByteArray.fromString(TEST_ORIGINAL, StandardCharsets.UTF_16))
			.isEqualTo(ByteArray.fromBase64String("_v8AdABlAHMAdABpAG4AZwAgAHMAdAByAGkAbgBn"))
			.isNotEqualTo(ByteArray.fromString(TEST_ORIGINAL, StandardCharsets.US_ASCII))
			.returns(false, ByteArray::isEmpty)
			.returns(30, ByteArray::size)
			.returns("_v8AdABlAHMAdABpAG4AZwAgAHMAdAByAGkAbgBn", ByteArray::encode)
			.returns(TEST_ORIGINAL, it -> new String(it.array(), StandardCharsets.UTF_16))
			.extracting(ByteArray::array)
			.isEqualTo(array.array());
	}

	@Test
	void shouldCreateByteArrayFromBase64String() {
		final var array = ByteArray.fromBase64String(TEST_ENCODED);

		assertThat(array).isNotNull()
			.isEqualTo(ByteArray.fromString("testing base64"))
			.isEqualTo(ByteArray.fromBase64String(TEST_ENCODED))
			.isNotEqualTo(ByteArray.fromString("testing base64 invalid"))
			.returns(false, ByteArray::isEmpty)
			.returns(14, ByteArray::size)
			.returns(TEST_ENCODED, ByteArray::encode)
			.returns("testing base64", it -> new String(it.array()))
			.extracting(ByteArray::array)
			.isEqualTo(array.array());
	}

	@Test
	void emptyByteArraysShouldBeEqual() {
		assertThat(ByteArray.empty()).isNotNull()
			.isEqualTo(ByteArray.empty())
			.returns(true, ByteArray::isEmpty)
			.returns(0, ByteArray::size)
			.returns("", ByteArray::encode)
			.returns("", it -> new String(it.array()))
			.extracting(ByteArray::array)
			.isEqualTo(new byte[0]);
	}

}