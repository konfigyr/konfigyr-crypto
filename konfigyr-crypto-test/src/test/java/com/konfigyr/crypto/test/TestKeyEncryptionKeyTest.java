package com.konfigyr.crypto.test;

import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.WrappedKeyMaterial;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

@DisplayName("TestKeyEncryptionKey")
class TestKeyEncryptionKeyTest {

	@Test
	@DisplayName("default instance has expected provider and identifier")
	void instanceHasExpectedProviderAndId() {
		assertThat(TestKeyEncryptionKey.INSTANCE)
			.returns("test-kek", KeyEncryptionKey::getId)
			.returns("test-provider", KeyEncryptionKey::getProvider);
	}

	@Test
	@DisplayName("constructor sets identifier and provider")
	void constructorSetsIdAndProvider() {
		final TestKeyEncryptionKey kek = new TestKeyEncryptionKey("my-id", "my-provider");

		assertThat(kek)
			.returns("my-id", KeyEncryptionKey::getId)
			.returns("my-provider", KeyEncryptionKey::getProvider);
	}

	@Test
	@DisplayName("wrap and unwrap round-trip recovers the original key material")
	void wrapAndUnwrapRoundTrip() throws IOException {
		final TestKeyEncryptionKey kek = new TestKeyEncryptionKey("id", "provider");
		final ByteArray original = ByteArray.fromString("secret-key-material");

		final WrappedKeyMaterial wrapped = kek.wrap(original);
		final ByteArray recovered = kek.unwrap(wrapped);

		assertThat(recovered).isEqualTo(original);
	}

	@Test
	@DisplayName("wrap produces different ciphertext for identical input due to random IV")
	void wrapProducesDifferentCiphertextForSameInput() throws IOException {
		final TestKeyEncryptionKey kek = new TestKeyEncryptionKey("id", "provider");
		final ByteArray data = ByteArray.fromString("same-data");

		final WrappedKeyMaterial first = kek.wrap(data);
		final WrappedKeyMaterial second = kek.wrap(data);

		assertThat(first).isNotEqualTo(second);
	}

	@Test
	@DisplayName("different instances cannot unwrap each other's wrapped material")
	void differentInstancesCannotUnwrapEachOther() throws IOException {
		final TestKeyEncryptionKey kek1 = new TestKeyEncryptionKey("id", "provider");
		final TestKeyEncryptionKey kek2 = new TestKeyEncryptionKey("id", "provider");

		final WrappedKeyMaterial wrapped = kek1.wrap(ByteArray.fromString("key-data"));

		assertThatExceptionOfType(IOException.class)
			.isThrownBy(() -> kek2.unwrap(wrapped));
	}

	@Test
	@DisplayName("unwrap throws IOException when material is corrupted")
	void unwrapThrowsWhenMaterialIsCorrupted() {
		final TestKeyEncryptionKey kek = new TestKeyEncryptionKey("id", "provider");
		final WrappedKeyMaterial corrupted = WrappedKeyMaterial.of(new byte[16]);

		assertThatExceptionOfType(IOException.class)
			.isThrownBy(() -> kek.unwrap(corrupted));
	}

}
