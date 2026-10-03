package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.Key;
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
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.FieldSource;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.ByteBuffer;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.within;

class X509KeysetTest {

	static final List<X509Algorithm> SIGNING = X509Algorithm.DEFAULT_ALGORITHMS.stream()
		.filter(algorithm -> algorithm.purpose() == KeysetPurpose.SIGNING)
		.toList();

	static final List<X509Algorithm> ENCRYPTION = X509Algorithm.DEFAULT_ALGORITHMS.stream()
		.filter(algorithm -> algorithm.purpose() == KeysetPurpose.ENCRYPTION)
		.toList();

	static final String KEY_ID = "0f8fad5b-d9cb-469f-a165-70867728950e";

	static final Instant NOT_AFTER = Instant.now().plus(Duration.ofDays(121));

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

	@MethodSource("blockedStatuses")
	@ParameterizedTest(name = "should throw {1} when the primary key is {0}")
	@DisplayName("should not sign, encrypt, verify or decrypt when the primary key is not enabled")
	void shouldRejectBlockedPrimaryKey(KeyStatus status, Class<? extends CryptoException.KeysetException> type) {
		final X509Keyset signing = keyset(X509Algorithm.EC_P256_SIGNING);
		final X509Keyset encryption = keyset(X509Algorithm.RSA_3072_ENCRYPTION);

		final ByteArray signature = signing.sign(data);
		final ByteArray cipher = encryption.encrypt(data);

		final X509Keyset blockedSigning = withPrimaryStatus(signing, status);
		final X509Keyset blockedEncryption = withPrimaryStatus(encryption, status);

		assertThatExceptionOfType(type)
			.isThrownBy(() -> blockedSigning.sign(data))
			.returns(signing.getName(), CryptoException.KeysetException::getName);

		assertThatExceptionOfType(type)
			.isThrownBy(() -> blockedEncryption.encrypt(data))
			.returns(encryption.getName(), CryptoException.KeysetException::getName);

		assertThatExceptionOfType(type)
			.isThrownBy(() -> blockedSigning.verify(signature, data))
			.withMessageStartingWith("Primary key '%s'", signing.getPrimary().getId());

		assertThatExceptionOfType(type)
			.isThrownBy(() -> blockedEncryption.decrypt(cipher))
			.withMessageStartingWith("Primary key '%s'", encryption.getPrimary().getId());
	}

	@MethodSource("blockedStatuses")
	@ParameterizedTest(name = "should throw {1} when the previous key is {0}")
	@DisplayName("should not verify or decrypt with a previous key that is not enabled")
	void shouldRejectBlockedPreviousKey(KeyStatus status, Class<? extends CryptoException.KeysetException> type) {
		final X509Keyset signing = keyset(X509Algorithm.EC_P256_SIGNING);
		final X509Keyset encryption = keyset(X509Algorithm.RSA_3072_ENCRYPTION);

		final ByteArray signature = signing.sign(data);
		final ByteArray cipher = encryption.encrypt(data);

		final X509Keyset rotatedSigning = withStatus(signing.rotate(), signing.getPrimary().getId(), status);
		final X509Keyset rotatedEncryption = withStatus(encryption.rotate(), encryption.getPrimary().getId(), status);

		assertThatExceptionOfType(type)
			.isThrownBy(() -> rotatedSigning.verify(signature, data))
			.withMessageStartingWith("Key '%s'", signing.getPrimary().getId());

		assertThatExceptionOfType(type)
			.isThrownBy(() -> rotatedEncryption.decrypt(cipher))
			.withMessageStartingWith("Key '%s'", encryption.getPrimary().getId());

		assertThat(rotatedSigning.verify(rotatedSigning.sign(data), data))
			.as("the enabled primary key must still verify its own signatures")
			.isTrue();

		assertThat(rotatedEncryption.decrypt(rotatedEncryption.encrypt(data)))
			.as("the enabled primary key must still decrypt its own cipher texts")
			.isEqualTo(data);

		assertThat(rotatedSigning.getKeys())
			.as("blocked keys must still be listed by the keyset")
			.hasSize(2);
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
			.withMessageContaining("No key found for the cipher text");
	}

	@Test
	@DisplayName("should only accept canonical UUIDs as key identifiers")
	void shouldRequireUuidKeyIdentifiers() {
		final KeyDefinition definition = KeyDefinition.of(X509Algorithm.EC_P256_SIGNING);

		assertThatIllegalArgumentException()
			.isThrownBy(() -> X509Key.generate(definition, "key-id", "test-keyset", NOT_AFTER))
			.withMessage("X509 key identifier must be a UUID, got: key-id");

		assertThatIllegalArgumentException()
			.isThrownBy(() -> X509Key.generate(definition, "1-1-1-1-1", "test-keyset", NOT_AFTER))
			.withMessageStartingWith("X509 key identifier must be a UUID in its canonical lower case form");

		assertThatIllegalArgumentException()
			.isThrownBy(() -> X509Key.generate(definition, KEY_ID.toUpperCase(), "test-keyset", NOT_AFTER))
			.withMessageStartingWith("X509 key identifier must be a UUID in its canonical lower case form");
	}

	@ParameterizedTest(name = "algorithm: {0}")
	@FieldSource("com.konfigyr.crypto.x509.X509AlgorithmTest#ALGORITHMS")
	@DisplayName("should generate key with a self-signed certificate matching the algorithm")
	void shouldGenerateSelfSignedCertificate(X509Algorithm algorithm) throws Exception {
		final X509Key key = X509Key.generate(KeyDefinition.builder()
			.algorithm(algorithm)
			.rotationInterval(Duration.ofDays(30))
			.build(), KEY_ID, "test-keyset", NOT_AFTER);

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

		assertThat(certificate.getNotBefore().toInstant())
			.isEqualTo(key.getCreatedAt().truncatedTo(ChronoUnit.SECONDS));

		assertThat(certificate.getNotAfter().toInstant())
			.isEqualTo(NOT_AFTER.truncatedTo(ChronoUnit.SECONDS));

		certificate.verify(certificate.getPublicKey());
	}

	@Test
	@DisplayName("should calculate the certificate validity from the keyset timings")
	void shouldCalculateCertificateValidity() {
		final Instant now = Instant.now();

		assertThat(X509Utils.certificateNotAfter(now, Duration.ofDays(90), Duration.ofDays(30)))
			.as("certificate must cover the rotation interval, the grace period and the margin")
			.isEqualTo(now.plus(Duration.ofDays(121)));

		assertThat(X509Utils.certificateNotAfter(now, null, null))
			.as("certificate must cover the maximum rotation interval when automatic rotation is disabled")
			.isEqualTo(now.plus(KeysetDefinition.MAXIMUM_ROTATION_INTERVAL).plus(Duration.ofDays(1)));

		assertThat(X509Utils.latestExpiration(now.plus(Duration.ofDays(121)), Duration.ofDays(30)))
			.isEqualTo(now.plus(Duration.ofDays(90)));
	}

	@Test
	@DisplayName("should issue a certificate covering the primary key and its retirement when rotating")
	void shouldIssueCertificateForPrimaryKey() {
		final Keyset rotated = keyset(X509Algorithm.EC_P256_SIGNING).rotate();
		final X509Key primary = (X509Key) rotated.getPrimary();

		assertThat(primary.getCertificate().getNotAfter().toInstant())
			.isCloseTo(Instant.now().plus(Duration.ofDays(121)), within(Duration.ofSeconds(5)));

		assertThat(primary.getExpiresAt())
			.isCloseTo(Instant.now().plus(Duration.ofDays(90)), within(Duration.ofSeconds(5)));
	}

	@Test
	@DisplayName("should issue a certificate for the next key that starts when the current primary key expires")
	void shouldIssueCertificateForNextKey() {
		final X509Keyset keyset = keyset(X509Algorithm.EC_P256_SIGNING);
		final Instant primaryExpiresAt = keyset.getPrimary().getExpiresAt();

		final X509Key next = (X509Key) keyset.rotate(KeyDefinition.builder()
				.algorithm(X509Algorithm.EC_P256_SIGNING)
				.rotationInterval(Duration.ofDays(90))
				.primary(false)
				.build())
			.getNextKey()
			.orElseThrow();

		assertThat(primaryExpiresAt)
			.isNotNull();

		assertThat(next.getCertificate().getNotAfter().toInstant())
			.as("next key certificate must cover its time as the primary key and its retirement")
			.isCloseTo(primaryExpiresAt.plus(Duration.ofDays(121)), within(Duration.ofSeconds(5)));
	}

	@Test
	@DisplayName("should cap the expiration time of a next key that is promoted later than planned")
	void shouldCapExpirationOfLatePromotion() {
		final X509Keyset keyset = keyset(X509Algorithm.EC_P256_SIGNING);

		// the next key was due to take over 10 days ago, its certificate ends 10 days earlier than required
		final Instant notAfter = X509Utils.certificateNotAfter(Instant.now().minus(Duration.ofDays(10)),
			Duration.ofDays(90), Duration.ofDays(30));

		final X509Keyset prepared = new X509Keyset.Builder(keyset)
			.keys(keyset.getKeys())
			.key(X509Key.generate(KeyDefinition.builder()
				.algorithm(X509Algorithm.EC_P256_SIGNING)
				.rotationInterval(Duration.ofDays(90))
				.primary(false)
				.build(), UUID.randomUUID().toString(), "test-keyset", notAfter))
			.build();

		final Key promoted = prepared.rotate().getPrimary();

		assertThat(promoted.getExpiresAt())
			.as("promoted key must expire so that it is retired before its certificate expires")
			.isEqualTo(notAfter.truncatedTo(ChronoUnit.SECONDS).minus(Duration.ofDays(31)))
			.isBefore(Instant.now().plus(Duration.ofDays(90)));
	}

	@Test
	@DisplayName("should not cap the expiration time of a promoted key when automatic rotation is disabled")
	void shouldNotCapExpirationWithoutRotation() {
		final KeysetDefinition definition = KeysetDefinition.builder()
			.name("test-keyset")
			.algorithm(X509Algorithm.EC_P256_SIGNING)
			.disableAutomaticKeyRotation()
			.build();

		final X509Keyset keyset = new X509Keyset.Builder(definition)
			.keyEncryptionKey(TestKeyEncryptionKey.INSTANCE)
			.key(X509Key.generate(KeyDefinition.of(definition), KEY_ID, definition.getName(), NOT_AFTER))
			.build();

		final Keyset prepared = keyset.rotate(KeyDefinition.builder()
			.algorithm(X509Algorithm.EC_P256_SIGNING)
			.primary(false)
			.build());

		final X509Key next = (X509Key) prepared.getNextKey().orElseThrow();

		assertThat(next.getCertificate().getNotAfter().toInstant())
			.isCloseTo(Instant.now().plus(KeysetDefinition.MAXIMUM_ROTATION_INTERVAL)
				.plus(Duration.ofDays(31)), within(Duration.ofSeconds(5)));

		assertThat(prepared.rotate().getPrimary().getExpiresAt())
			.isNull();
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
			.key(X509Key.generate(KeyDefinition.of(definition), KEY_ID, definition.getName(), NOT_AFTER))
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

	static X509Keyset withPrimaryStatus(X509Keyset keyset, KeyStatus status) {
		return withStatus(keyset, keyset.getPrimary().getId(), status);
	}

	static X509Keyset withStatus(Keyset keyset, String keyId, KeyStatus status) {
		final X509Keyset.Builder builder = new X509Keyset.Builder((X509Keyset) keyset);

		keyset.getKeys().stream().map(X509Key.class::cast).forEach(key -> builder.key(key.getId().equals(keyId)
			? new X509Key.Builder(key).status(status).build()
			: key));

		return builder.build();
	}

	static Stream<Arguments> blockedStatuses() {
		return Stream.of(
			Arguments.of(KeyStatus.COMPROMISED, CryptoException.KeysetCompromisedException.class),
			Arguments.of(KeyStatus.COMPROMISED_PENDING_DESTRUCTION, CryptoException.KeysetCompromisedException.class),
			Arguments.of(KeyStatus.DISABLED, CryptoException.KeysetDisabledException.class),
			Arguments.of(KeyStatus.PENDING_DESTRUCTION, CryptoException.KeysetPendingDestructionException.class),
			Arguments.of(KeyStatus.DESTROYED, CryptoException.KeysetDestroyedException.class),
			Arguments.of(KeyStatus.INITIALIZING, CryptoException.KeysetUnavailableException.class),
			Arguments.of(KeyStatus.INITIALIZATION_FAILED, CryptoException.KeysetUnavailableException.class),
			Arguments.of(KeyStatus.DESTRUCTION_FAILED, CryptoException.KeysetUnavailableException.class)
		);
	}

}
