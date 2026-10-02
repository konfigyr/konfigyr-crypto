package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetOperation;
import com.konfigyr.crypto.KeysetPurpose;
import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.FieldSource;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class X509KeysetTest {

	static final List<X509Algorithm> SIGNING = X509Algorithm.DEFAULT_ALGORITHMS.stream()
		.filter(algorithm -> algorithm.purpose() == KeysetPurpose.SIGNING)
		.toList();

	static final List<X509Algorithm> ENCRYPTION = X509Algorithm.DEFAULT_ALGORITHMS.stream()
		.filter(algorithm -> algorithm.purpose() == KeysetPurpose.ENCRYPTION)
		.toList();

	static final String KEY_ID = "0f8fad5b-d9cb-469f-a165-70867728950e";

	final ByteArray data = ByteArray.fromString("konfigyr-crypto-x509-data");

	@ParameterizedTest(name = "algorithm: {0}")
	@FieldSource("SIGNING")
	@DisplayName("should sign and verify data")
	void shouldSignAndVerify(X509Algorithm algorithm) {
		final Keyset keyset = keyset(algorithm);
		final ByteArray signature = keyset.sign(data);

		assertThat(keyset.verify(signature, data))
			.as("signature must be valid for the signed data")
			.isTrue();

		assertThat(keyset.verify(signature, ByteArray.fromString("tampered-data")))
			.as("signature must not be valid for tampered data")
			.isFalse();

		assertThat(keyset.verify(ByteArray.fromString("garbage"), data))
			.as("garbage signature must not be valid")
			.isFalse();

		assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
			.isThrownBy(() -> keyset.encrypt(data))
			.returns(KeysetOperation.ENCRYPT, CryptoException.KeysetOperationException::attemptedOperation);
	}

	@ParameterizedTest(name = "algorithm: {0}")
	@FieldSource("ENCRYPTION")
	@DisplayName("should encrypt and decrypt data with an optional context")
	void shouldEncryptAndDecrypt(X509Algorithm algorithm) {
		final Keyset keyset = keyset(algorithm);
		final ByteArray context = ByteArray.fromString("konfigyr-crypto-x509-context");

		assertThat(keyset.decrypt(keyset.encrypt(data)))
			.isEqualTo(data);

		final ByteArray cipher = keyset.encrypt(data, context);

		assertThat(keyset.decrypt(cipher, context))
			.isEqualTo(data);

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.as("decryption must fail with a different context")
			.isThrownBy(() -> keyset.decrypt(cipher, ByteArray.fromString("wrong-context")))
			.returns(KeysetOperation.DECRYPT, CryptoException.KeysetOperationException::attemptedOperation);

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.as("decryption must fail without the context")
			.isThrownBy(() -> keyset.decrypt(cipher))
			.returns(KeysetOperation.DECRYPT, CryptoException.KeysetOperationException::attemptedOperation);

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.as("decryption must fail for garbage")
			.isThrownBy(() -> keyset.decrypt(ByteArray.fromString("garbage")))
			.returns(KeysetOperation.DECRYPT, CryptoException.KeysetOperationException::attemptedOperation);

		assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
			.isThrownBy(() -> keyset.sign(data))
			.returns(KeysetOperation.SIGN, CryptoException.KeysetOperationException::attemptedOperation);
	}

	@Test
	@DisplayName("should reject data that exceeds the RSA-OAEP plaintext limit")
	void shouldRejectOversizedPlaintext() {
		final Keyset keyset = keyset(X509Algorithm.RSA_3072_ENCRYPTION);

		assertThat(keyset.encrypt(new ByteArray(new byte[318])))
			.isNotNull();

		assertThatIllegalArgumentException()
			.isThrownBy(() -> keyset.encrypt(new ByteArray(new byte[319])))
			.withMessage("Cannot encrypt more than 318 bytes with RSA-OAEP and a 3072-bit key, got: 319");
	}

	@Test
	@DisplayName("should reject empty inputs")
	void shouldRejectEmptyInputs() {
		final Keyset signing = keyset(X509Algorithm.EC_P256_SIGNING);
		final Keyset encryption = keyset(X509Algorithm.RSA_3072_ENCRYPTION);

		assertThatIllegalArgumentException().isThrownBy(() -> signing.sign(ByteArray.empty()));
		assertThatIllegalArgumentException().isThrownBy(() -> signing.verify(ByteArray.empty(), data));
		assertThatIllegalArgumentException().isThrownBy(() -> signing.verify(data, ByteArray.empty()));
		assertThatIllegalArgumentException().isThrownBy(() -> encryption.encrypt(ByteArray.empty()));
		assertThatIllegalArgumentException().isThrownBy(() -> encryption.decrypt(ByteArray.empty()));
	}

	@Test
	@DisplayName("should verify and decrypt with previous keys after rotation")
	void shouldRetainAccessAfterRotation() {
		final Keyset signing = keyset(X509Algorithm.RSA_3072_SIGNING);
		final Keyset encryption = keyset(X509Algorithm.RSA_3072_ENCRYPTION);

		final ByteArray signature = signing.sign(data);
		final ByteArray cipher = encryption.encrypt(data);

		final Keyset rotatedSigning = signing.rotate();
		final Keyset rotatedEncryption = encryption.rotate();

		assertThat(rotatedSigning.getKeys())
			.hasSize(2)
			.filteredOn(key -> key.isPrimary())
			.hasSize(1)
			.first()
			.isNotEqualTo(signing.getPrimary());

		assertThat(rotatedSigning.verify(signature, data))
			.isTrue();

		assertThat(rotatedSigning.sign(data))
			.isNotEqualTo(signature);

		assertThat(rotatedEncryption.decrypt(cipher))
			.isEqualTo(data);
	}

	@Test
	@DisplayName("should not verify or decrypt with compromised keys")
	void shouldRejectCompromisedKeys() {
		final X509Keyset signing = keyset(X509Algorithm.EC_P256_SIGNING);
		final X509Keyset encryption = keyset(X509Algorithm.RSA_3072_ENCRYPTION);

		final ByteArray signature = signing.sign(data);
		final ByteArray cipher = encryption.encrypt(data);

		final X509Keyset compromisedSigning = compromise(signing);
		final X509Keyset compromisedEncryption = compromise(encryption);

		assertThat(compromisedSigning.verify(signature, data))
			.isFalse();

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.isThrownBy(() -> compromisedEncryption.decrypt(cipher));

		assertThatExceptionOfType(CryptoException.KeysetCompromisedException.class)
			.isThrownBy(() -> compromisedSigning.sign(data));
	}

	@Test
	@DisplayName("should prefix cipher texts and signatures with the version byte and the key identifier UUID")
	void shouldPrefixWithKeyIdentifierUuid() {
		final X509Keyset signing = keyset(X509Algorithm.EC_P256_SIGNING);
		final X509Keyset encryption = keyset(X509Algorithm.RSA_3072_ENCRYPTION);

		assertThat(signing.sign(data).slice(0, 17))
			.isEqualTo(header(signing));

		assertThat(encryption.encrypt(data))
			.returns(17 + 384, ByteArray::size)
			.extracting(cipher -> cipher.slice(0, 17))
			.isEqualTo(header(encryption));
	}

	@Test
	@DisplayName("should not verify or decrypt payloads that reference an unknown key")
	void shouldRejectUnknownKeyIdentifier() {
		final X509Keyset signing = keyset(X509Algorithm.EC_P256_SIGNING);
		final X509Keyset encryption = keyset(X509Algorithm.RSA_3072_ENCRYPTION);

		final ByteArray signature = signing.sign(data);
		final ByteArray cipher = encryption.encrypt(data);

		assertThat(signing.verify(withUnknownKey(signature), data))
			.isFalse();

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.isThrownBy(() -> encryption.decrypt(withUnknownKey(cipher)))
			.withMessageContaining("No usable key found for the cipher text");
	}

	@Test
	@DisplayName("should only accept canonical UUIDs as key identifiers")
	void shouldRequireUuidKeyIdentifiers() {
		final KeyDefinition definition = KeyDefinition.of(X509Algorithm.EC_P256_SIGNING);

		assertThatIllegalArgumentException()
			.isThrownBy(() -> X509Key.generate(definition, "key-id", "test-keyset"))
			.withMessage("X509 key identifier must be a UUID, got: key-id");

		assertThatIllegalArgumentException()
			.isThrownBy(() -> X509Key.generate(definition, "1-1-1-1-1", "test-keyset"))
			.withMessageStartingWith("X509 key identifier must be a UUID in its canonical lower case form");

		assertThatIllegalArgumentException()
			.isThrownBy(() -> X509Key.generate(definition, KEY_ID.toUpperCase(), "test-keyset"))
			.withMessageStartingWith("X509 key identifier must be a UUID in its canonical lower case form");
	}

	@ParameterizedTest(name = "algorithm: {0}")
	@FieldSource("com.konfigyr.crypto.x509.X509AlgorithmTest#ALGORITHMS")
	@DisplayName("should generate key with a self-signed certificate matching the algorithm")
	void shouldGenerateSelfSignedCertificate(X509Algorithm algorithm) throws Exception {
		final X509Key key = X509Key.generate(KeyDefinition.builder()
			.algorithm(algorithm)
			.rotationInterval(Duration.ofDays(30))
			.build(), KEY_ID, "test-keyset");

		final X509Certificate certificate = key.getCertificate();

		assertThat(key)
			.returns(KEY_ID, X509Key::getId)
			.returns(KeyStatus.ENABLED, X509Key::getStatus)
			.returns(true, X509Key::isPrimary)
			.returns(List.of(certificate), X509Key::getCertificateChain);

		assertThat(certificate.getSubjectX500Principal())
			.isEqualTo(certificate.getIssuerX500Principal())
			.hasToString("CN=test-keyset");

		assertThat(certificate.getSigAlgName())
			.isEqualToIgnoringCase(algorithm.signatureAlgorithm());

		assertThat(certificate.getBasicConstraints())
			.as("certificate must not be a CA certificate")
			.isEqualTo(-1);

		// key usage: [0] digitalSignature, [2] keyEncipherment
		assertThat(certificate.getKeyUsage()[0])
			.isEqualTo(algorithm.purpose() == KeysetPurpose.SIGNING);
		assertThat(certificate.getKeyUsage()[2])
			.isEqualTo(algorithm.purpose() == KeysetPurpose.ENCRYPTION);

		assertThat(certificate.getNotAfter().toInstant())
			.isEqualTo(key.getExpiresAt().truncatedTo(ChronoUnit.SECONDS));

		certificate.verify(certificate.getPublicKey());
	}

	@Test
	@DisplayName("should not expose private key material through toString")
	void shouldNotExposePrivateKey() {
		final X509Keyset keyset = keyset(X509Algorithm.RSA_3072_SIGNING);
		final X509Key key = (X509Key) keyset.getPrimary();
		final String encoded = new ByteArray(key.privateKey().getEncoded()).encodeBase64();

		assertThat(keyset.toString())
			.doesNotContain(encoded)
			.doesNotContain("PrivateKey");
	}

	static X509Keyset keyset(X509Algorithm algorithm) {
		final KeysetDefinition definition = KeysetDefinition.of("test-keyset", algorithm);

		return new X509Keyset.Builder(definition)
			.keyEncryptionKey(TestKeyEncryptionKey.INSTANCE)
			.key(X509Key.generate(KeyDefinition.of(definition), KEY_ID, definition.getName()))
			.build();
	}

	static ByteArray header(X509Keyset keyset) {
		final UUID id = UUID.fromString(keyset.getPrimary().getId());

		return new ByteArray(ByteBuffer.allocate(17)
			.put((byte) 0x01)
			.putLong(id.getMostSignificantBits())
			.putLong(id.getLeastSignificantBits())
			.array());
	}

	static ByteArray withUnknownKey(ByteArray value) {
		final byte[] bytes = value.array();
		bytes[16] ^= 0x01;
		return new ByteArray(bytes);
	}

	static X509Keyset compromise(X509Keyset keyset) {
		final X509Key primary = (X509Key) keyset.getPrimary();

		return new X509Keyset.Builder(keyset)
			.key(new X509Key.Builder(primary).status(KeyStatus.COMPROMISED).build())
			.build();
	}

}
