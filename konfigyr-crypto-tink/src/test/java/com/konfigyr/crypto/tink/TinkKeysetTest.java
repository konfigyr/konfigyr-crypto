package com.konfigyr.crypto.tink;

import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import org.assertj.core.data.TemporalUnitWithinOffset;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.DisabledOnOs;
import org.junit.jupiter.api.condition.OS;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.*;

class TinkKeysetTest extends AbstractCryptoTest {

	@Test
	@DisplayName("should perform encryption using tink AEAD primitive")
	void shouldPerformAeadEncryptionOperation() throws Exception {
		final var keyset = generate("test", TinkAlgorithm.AES128_GCM);
		final var cypher = keyset.encrypt(DATA);

		assertThat(cypher).isNotNull();
		assertThat(keyset.decrypt(cypher)).isEqualTo(DATA);

		assertThatThrownBy(() -> keyset.decrypt(cypher, CONTEXT))
			.satisfies(assertOperationException("test", KeysetOperation.DECRYPT));

		assertThatThrownBy(() -> generate("test", TinkAlgorithm.AES128_GCM).decrypt(cypher))
			.satisfies(assertOperationException("test", KeysetOperation.DECRYPT));
	}

	@Test
	@DisplayName("should perform encryption using tink AEAD primitive using context")
	void shouldPerformAeadEncryptionOperationWithContext() throws Exception {
		final var keyset = generate("test", TinkAlgorithm.AES128_CTR_HMAC_SHA256);
		final var cypher = keyset.encrypt(DATA, CONTEXT);

		assertThat(cypher).isNotNull();
		assertThat(keyset.decrypt(cypher, CONTEXT)).isEqualTo(DATA);

		assertThatThrownBy(() -> keyset.decrypt(cypher))
			.satisfies(assertOperationException("test", KeysetOperation.DECRYPT));

		assertThatThrownBy(() -> generate("test", TinkAlgorithm.AES128_GCM).decrypt(cypher, CONTEXT))
			.satisfies(assertOperationException("test", KeysetOperation.DECRYPT));
	}

	@Test
	@DisplayName("should perform encryption using tink HybridEncrypt primitive")
	void shouldPerformHybridEncryptionOperation() throws Exception {
		final var keyset = generate("test", TinkAlgorithm.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM);
		final var cypher = keyset.encrypt(DATA);

		assertThat(cypher).isNotNull();
		assertThat(keyset.decrypt(cypher)).isEqualTo(DATA);

		assertThatThrownBy(() -> keyset.decrypt(cypher, CONTEXT))
			.satisfies(assertOperationException("test", KeysetOperation.DECRYPT));

		assertThatThrownBy(
				() -> generate("test", TinkAlgorithm.DHKEM_X25519_HKDF_SHA256_HKDF_SHA256_AES_128_GCM).decrypt(cypher))
			.satisfies(assertOperationException("test", KeysetOperation.DECRYPT));
	}

	@Test
	@DisplayName("should perform encryption using tink HybridEncrypt primitive using context")
	void shouldPerformHybridEncryptionOperationWithContext() throws Exception {
		final var keyset = generate("test", TinkAlgorithm.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM);
		final var cypher = keyset.encrypt(DATA, CONTEXT);

		assertThat(cypher).isNotNull();
		assertThat(keyset.decrypt(cypher, CONTEXT)).isEqualTo(DATA);

		assertThatThrownBy(() -> keyset.decrypt(cypher))
			.satisfies(assertOperationException("test", KeysetOperation.DECRYPT));

		assertThatThrownBy(() -> generate("test", TinkAlgorithm.ECIES_P256_HKDF_HMAC_SHA256_AES128_GCM).decrypt(cypher))
			.satisfies(assertOperationException("test", KeysetOperation.DECRYPT));
	}

	@Test
	@DisplayName("should perform signing operation")
	void shouldPerformSigningOperation() throws Exception {
		final var keyset = generate("test", TinkAlgorithm.ECDSA_P256);
		final var signature = keyset.sign(DATA);

		assertThat(signature).isNotNull();
		assertThat(keyset.verify(signature, DATA)).isTrue();

		assertThat(keyset.verify(signature, ByteArray.fromString("Other data"))).isFalse();
		assertThat(keyset.verify(ByteArray.fromString("Other signature"), DATA)).isFalse();
		assertThat(generate("test", TinkAlgorithm.ECDSA_P256).verify(signature, DATA)).isFalse();
	}

	@Test
	@DisabledOnOs(value = OS.WINDOWS)
	@DisplayName("should rotate keyset by adding a new key in the Tink keyset handle")
	void shouldRotateKeyset() throws Exception {
		final var keyset = generate("rotating-keyset", TinkAlgorithm.AES128_GCM);
		final var rotated = keyset.rotate();

		assertThatObject(rotated).isNotNull()
			.isNotEqualTo(keyset)
			.isInstanceOf(TinkKeyset.class)
			.returns(keyset.getName(), Keyset::getName)
			.returns(keyset.getAlgorithm(), Keyset::getAlgorithm)
			.returns(keyset.getKeyEncryptionKey(), Keyset::getKeyEncryptionKey)
			.returns(keyset.getRotationInterval(), Keyset::getRotationInterval)
			.satisfies(it -> assertThat(it.getNextRotationTime()).isAfter(keyset.getNextRotationTime())
				.isCloseTo(Instant.now().plus(it.getRotationInterval()),
						new TemporalUnitWithinOffset(1, ChronoUnit.SECONDS)))
			.satisfies(it -> assertThat(it.getKeys()).isNotNull()
				.hasSize(2)
				.extracting(Key::getType, Key::getStatus, Key::isPrimary)
				.containsExactlyInAnyOrder(tuple(KeyType.OCTET, KeyStatus.ENABLED, true),
						tuple(KeyType.OCTET, KeyStatus.ENABLED, false)))
			.satisfies(it -> assertThat(it.getKey(keyset.getKeys().get(0).getId())).isPresent()
				.get()
				.returns(false, Key::isPrimary));
	}

	@Test
	@DisplayName("should fail to perform unsupported keyset operation")
	void shouldFailToPerformUnsupportedOperation() {
		assertThatThrownBy(() -> generate("test", TinkAlgorithm.ECDSA_P256).encrypt(DATA))
			.satisfies(assertOperationException(CryptoException.UnsupportedKeysetOperationException.class, "test",
					KeysetOperation.ENCRYPT));
		assertThatThrownBy(() -> generate("test", TinkAlgorithm.ECDSA_P256).decrypt(DATA))
			.satisfies(assertOperationException(CryptoException.UnsupportedKeysetOperationException.class, "test",
					KeysetOperation.DECRYPT));

		assertThatThrownBy(() -> generate("test", TinkAlgorithm.AES128_GCM).sign(DATA))
			.satisfies(assertOperationException(CryptoException.UnsupportedKeysetOperationException.class, "test",
					KeysetOperation.SIGN));
		assertThatThrownBy(() -> generate("test", TinkAlgorithm.AES128_GCM).verify(DATA, DATA))
			.satisfies(assertOperationException(CryptoException.UnsupportedKeysetOperationException.class, "test",
					KeysetOperation.VERIFY));
	}

}
