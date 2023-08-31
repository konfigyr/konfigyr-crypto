package com.konfigyr.crypto.tink;

import com.google.crypto.tink.KeysetHandle;
import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetOperation;
import com.konfigyr.io.ByteArray;
import org.assertj.core.data.TemporalUnitWithinOffset;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TinkKeysetTest extends AbstractCryptoTest {

	@Test
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
	void shouldRotateKeyset() throws Exception {
		final var keyset = generate("rotating-keyset", TinkAlgorithm.AES128_GCM);

		assertThat(keyset.rotate()).isNotNull()
			.isNotEqualTo(keyset)
			.isInstanceOf(TinkKeyset.class)
			.returns(keyset.getName(), Keyset::getName)
			.returns(keyset.getAlgorithm(), Keyset::getAlgorithm)
			.returns(keyset.getKeyEncryptionKey(), Keyset::getKeyEncryptionKey)
			.returns(keyset.getRotationInterval(), Keyset::getRotationInterval)
			.satisfies(it -> assertThat(it.getNextRotationTime()).isAfter(keyset.getNextRotationTime())
				.isCloseTo(Instant.now().plus(it.getRotationInterval()),
						new TemporalUnitWithinOffset(1, ChronoUnit.SECONDS)))
			.satisfies(it -> assertThat(it).extracting(TinkKeyset.class::cast)
				.extracting(TinkKeyset::getHandle)
				.returns(2, KeysetHandle::size)
				.extracting(KeysetHandle::getKeysetInfo)
				.isNotEqualTo(((TinkKeyset) keyset).getHandle().getKeysetInfo()));
	}

	@Test
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