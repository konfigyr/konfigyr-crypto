package com.konfigyr.crypto.tink;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KmsClient;
import com.google.crypto.tink.KmsClients;
import com.google.crypto.tink.subtle.AesGcmJce;
import com.google.crypto.tink.subtle.Random;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.io.ByteArray;
import org.assertj.core.api.ThrowingConsumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.platform.commons.util.ReflectionUtils;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.GeneralSecurityException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.notNull;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TinkKeyEncryptionKeyTest extends AbstractCryptoTest {

	@Mock
	KmsClient kms;

	Aead aead;

	TinkKeyEncryptionKey.Builder builder;

	@BeforeEach
	void setup() throws Exception {
		builder = TinkKeyEncryptionKey.builder("test-provider");
		aead = spy(new AesGcmJce(Random.randBytes(16)));

		KmsClients.add(kms);
	}

	@AfterEach
	void cleanup() {
		final var reset = ReflectionUtils.findMethod(KmsClients.class, "reset");
		ReflectionUtils.invokeMethod(reset.orElseThrow(), null);
	}

	@Test
	@DisplayName("should generate random key encryption keys")
	void shouldGenerateRandomKek() {
		final var kek = builder.generate("test-kek");

		assertThat(kek).returns("test-kek", KeyEncryptionKey::getId)
			.returns("test-provider", KeyEncryptionKey::getProvider)
			.returns("test-provider@test-kek", KeyEncryptionKey::toString)
			.satisfies(assertEncryptsKeyset());
	}

	@Test
	@DisplayName("should generate key encryption key from a secret key")
	void shouldGenerateSecretKek() {
		final var kek = builder.from("test-kek", new SecretKeySpec(Random.randBytes(16), "AES"));

		assertThat(kek).returns("test-kek", KeyEncryptionKey::getId)
			.returns("test-provider", KeyEncryptionKey::getProvider)
			.returns("test-provider@test-kek", KeyEncryptionKey::toString)
			.satisfies(assertEncryptsKeyset());
	}

	@Test
	@DisplayName("should generate key encryption key from a KMS URI")
	void shouldCreateKmsKek() throws GeneralSecurityException {
		doReturn(true).when(kms).doesSupport("test-kek-uri");
		doReturn(aead).when(kms).getAead("test-kek-uri");

		final var kek = builder.kms("test-kek-uri");

		assertThat(kek).returns("test-kek-uri", KeyEncryptionKey::getId)
			.returns("test-provider", KeyEncryptionKey::getProvider)
			.returns("test-provider@test-kek-uri", KeyEncryptionKey::toString)
			.satisfies(assertEncryptsKeyset());

		verify(aead).encrypt(eq(DATA.array()), eq(null));
		verify(aead).decrypt(any(), eq(null));
	}

	@Test
	@DisplayName("should generate key encryption key from a KMS URI with DEK enveloping")
	void shouldCreateEnvelopeKmsKek() throws GeneralSecurityException {
		doReturn(true).when(kms).doesSupport("test-kek-uri");
		doReturn(aead).when(kms).getAead("test-kek-uri");

		final var kek = builder.kms("test-kek-uri", "AES128_GCM");

		assertThat(kek).returns("test-kek-uri", KeyEncryptionKey::getId)
			.returns("test-provider", KeyEncryptionKey::getProvider)
			.returns("test-provider@test-kek-uri", KeyEncryptionKey::toString)
			.satisfies(assertEncryptsKeyset());

		verify(aead, times(0)).encrypt(eq(DATA.array()), any());
		verify(aead).encrypt(any(), notNull());
		verify(aead).decrypt(any(), notNull());
	}

	@Test
	@DisplayName("should fail to create key encryption key from invalid secret key")
	void shouldFailToCreateKekFromInvalidSecretKey() {
		assertThatThrownBy(() -> builder.from("test-kek", ByteArray.empty()))
			.isInstanceOf(IllegalArgumentException.class)
			.hasRootCauseInstanceOf(GeneralSecurityException.class)
			.hasMessage("Failed to create AES Key Encryption Key with id: test-kek");
	}

	@Test
	@DisplayName("should fail to create key encryption key from invalid KMS URI")
	void shouldFailToCreateKmsKekDueToUnsupportedKmsClient() {
		final var kek = builder.kms("test-kek-uri");

		assertThat(kek).returns("test-kek-uri", KeyEncryptionKey::getId)
			.returns("test-provider", KeyEncryptionKey::getProvider)
			.returns("test-provider@test-kek-uri", KeyEncryptionKey::toString)
			.satisfies(it -> assertThatThrownBy(() -> it.wrap(DATA)).isInstanceOf(IOException.class)
				.hasRootCauseInstanceOf(GeneralSecurityException.class)
				.hasRootCauseMessage("No KMS client does support: test-kek-uri"));
	}

	@Test
	@DisplayName("should fail to create key encryption key from invalid KMS URI with DEK enveloping")
	void shouldFailToCreateEnvelopKmsKekDueToUnsupportedKmsClient() {
		final var kek = builder.kms("test-kek-uri", "AES128_GCM");

		assertThat(kek).returns("test-kek-uri", KeyEncryptionKey::getId)
			.returns("test-provider", KeyEncryptionKey::getProvider)
			.returns("test-provider@test-kek-uri", KeyEncryptionKey::toString)
			.satisfies(it -> assertThatThrownBy(() -> it.wrap(DATA)).isInstanceOf(IOException.class)
				.hasRootCauseInstanceOf(GeneralSecurityException.class)
				.hasRootCauseMessage("No KMS client does support: test-kek-uri"));
	}

	@Test
	@DisplayName("should fail to create key encryption key from invalid DEK template")
	void shouldFailToCreateEnvelopKmsKekDueToUnsupportedDEKTemplate() {
		assertThatThrownBy(() -> builder.kms("test-kek-uri", "DEK_TEMPLATE"))
			.isInstanceOf(IllegalArgumentException.class)
			.hasRootCauseInstanceOf(GeneralSecurityException.class)
			.hasMessage("Could not resolve Tink Key Template for: DEK_TEMPLATE");
	}

	private static ThrowingConsumer<KeyEncryptionKey> assertEncryptsKeyset() {
		return kek -> {
			final var cipher = kek.wrap(DATA);

			assertThat(DATA).isEqualTo(kek.unwrap(cipher));
		};

	}

}
