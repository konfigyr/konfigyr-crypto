package com.konfigyr.crypto;

import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.NotSerializableException;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.*;

class WrappedKeyMaterialTest {

	@Test
	@DisplayName("should create WrappedKeyMaterial from ByteArray")
	void shouldCreateWrappedKeyMaterialFromByteArray() {
		final var bytes = ByteArray.fromString("test-key-material");

		assertThat(WrappedKeyMaterial.of(bytes))
			.isNotNull()
			.returns(bytes.array(), WrappedKeyMaterial::toByteArray);
	}

	@Test
	@DisplayName("should create WrappedKeyMaterial from primitive byte array")
	void shouldCreateWrappedKeyMaterialFromPrimitiveByteArray() {
		final var bytes = "test-key-material".getBytes();

		assertThat(WrappedKeyMaterial.of(bytes))
			.isNotNull()
			.returns(bytes, WrappedKeyMaterial::toByteArray);
	}

	@Test
	@DisplayName("should create WrappedKeyMaterial from String")
	void shouldCreateWrappedKeyMaterialFromString() {
		final var value = "test-key-material";

		assertThat(WrappedKeyMaterial.of(value))
			.isNotNull()
			.returns(value.getBytes(StandardCharsets.UTF_8), WrappedKeyMaterial::toByteArray);
	}

	@Test
	@DisplayName("should throw exception when ByteArray is null or empty")
	void shouldThrowExceptionWhenByteArrayIsEmpty() {
		assertThatThrownBy(() -> WrappedKeyMaterial.of(ByteArray.empty()))
			.isInstanceOf(IllegalArgumentException.class)
			.hasMessageContaining("Wrapped key material bytes can't be empty");
	}

	@Test
	@DisplayName("should return a copy of byte array from toByteArray()")
	void shouldReturnByteArrayFromToByteArray() {
		byte[] originalBytes = "test-key-material".getBytes();

		assertThat(WrappedKeyMaterial.of(originalBytes).toByteArray())
			.isEqualTo(originalBytes)
			.isNotSameAs(originalBytes);
	}

	@Test
	@DisplayName("should open an InputStream from the provided byte array")
	void shouldReturnByteArrayFromInputStream() {
		byte[] originalBytes = "test-key-material".getBytes();

		assertThat(WrappedKeyMaterial.of(originalBytes).getInputStream())
			.hasBinaryContent(originalBytes);
	}

	@Test
	@DisplayName("should implement equals() and hashCode() correctly")
	void shouldImplementEqualsAndHashCode() {
		byte[] bytes = "test-key-material".getBytes();
		WrappedKeyMaterial material1 = WrappedKeyMaterial.of(bytes);
		WrappedKeyMaterial material2 = WrappedKeyMaterial.of(bytes);
		WrappedKeyMaterial material3 = WrappedKeyMaterial.of("different-material".getBytes());

		assertThat(material1)
			.isEqualTo(material2)
			.isNotEqualTo(material3)
			.isNotEqualTo(null)
			.isNotEqualTo("some-string");

		assertThat(material1)
			.hasSameHashCodeAs(material2)
			.doesNotHaveSameHashCodeAs(material3);
	}

	@Test
	@DisplayName("should return formatted string from toString()")
	void shouldReturnFormattedStringFromToString() {
		byte[] bytes = "test-key-material".getBytes();

		assertThat(WrappedKeyMaterial.of(bytes))
			.hasToString("WrappedKeyMaterial[%d bytes]", bytes.length);
	}

	@Test
	@DisplayName("should not be Java-serializable")
	void shouldNotBeSerializable() {
		assertThatExceptionOfType(NotSerializableException.class).isThrownBy(() -> {
			try (var out = new ObjectOutputStream(new ByteArrayOutputStream())) {
				out.writeObject(WrappedKeyMaterial.of("test-key-material"));
			}
		});
	}

}
