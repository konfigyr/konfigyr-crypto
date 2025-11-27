package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.*;
import com.konfigyr.io.ByteArray;
import com.nimbusds.jose.*;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.KeyOperation;
import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Stream;

import static org.assertj.core.api.Assertions.*;

class JsonWebKeysetTest extends AbstractCryptoTest {

	@MethodSource("signingAlgorithms")
	@ParameterizedTest(name = "using algorithm: {0}")
	@DisplayName("should sign byte array and verify digital signature")
	void shouldPerformSignatureOperations(JoseAlgorithm algorithm) throws Exception {
		final var data = ByteArray.fromString("data to be signed");
		final var key = generate("test-rs384", algorithm);

		assertThat(key.getAlgorithm().operations())
			.as("Keyset operations for algorithm %s myst be SIGN and VERIFY", algorithm.name())
			.containsExactlyInAnyOrder(KeysetOperation.SIGN, KeysetOperation.VERIFY);

		final var signature = key.sign(data);

		assertThat(signature)
			.as("Generated JWS must not be null")
			.isNotNull();

		final var jws = JWSObject.parse(new String(signature.array(), StandardCharsets.UTF_8));

		assertThat(jws.getHeader().getAlgorithm())
			.as("JWS algorithm must match keyset algorithm")
			.isEqualTo(algorithm.algorithm());

		assertThat(jws.getHeader().getKeyID())
			.as("JWS key ID must be set in the JWS header")
			.isNotEmpty();

		assertThat(jws.getSignature())
			.as("JWS signature must not be null")
			.isNotNull();

		assertThat(key.verify(signature, data))
			.as("Signature must be valid")
			.isTrue();
	}

	@MethodSource("encryptionAlgorithms")
	@ParameterizedTest(name = "using algorithm: {0}")
	@DisplayName("should encrypt byte array and decrypt it")
	void shouldPerformEncryptionOperations(JoseAlgorithm algorithm) throws Exception {
		final var data = ByteArray.fromString("data to be encrypted");
		final var key = generate("test-rs384", algorithm);

		assertThat(key.getAlgorithm().operations())
			.as("Keyset operations for algorithm %s myst be ENCRYPT and DECRYPT", algorithm.name())
			.containsExactlyInAnyOrder(KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT);

		final var cipher = key.encrypt(data);

		assertThat(cipher)
			.as("Generated JWE must not be null")
			.isNotNull();

		final var jwe = JWEObject.parse(new String(cipher.array(), StandardCharsets.UTF_8));

		assertThat(jwe.getHeader().getAlgorithm())
			.as("JWE algorithm must match keyset algorithm")
			.isEqualTo(algorithm.algorithm());

		assertThat(jwe.getHeader().getEncryptionMethod())
			.as("JWE encryption algorithm must be %s", EncryptionMethod.A256GCM)
			.isEqualTo(EncryptionMethod.A256GCM);

		assertThat(jwe.getHeader().getKeyID())
			.as("JWE key ID must be set in the JWE header")
			.isNotEmpty();

		assertThat(jwe.getCipherText())
			.as("JWE must contain the encrypted content")
			.isNotNull();

		assertThat(key.decrypt(cipher))
			.as("Should decrypt encrypted data back to original")
			.isEqualTo(data);
	}

	@Test
	@DisplayName("should select JWK from keyset")
	void shouldSelectKey() throws IOException {
		final var keyset = (JsonWebKeyset) generate("selecting-keyset", JoseAlgorithm.RS256).rotate();

		final var selector = new JWKSelector(
			new JWKMatcher.Builder()
				.algorithm(JWSAlgorithm.RS256)
				.keyID(keyset.getKeys().get(0).getId())
				.build()
		);

		assertThat(keyset.get(selector, null))
			.isNotNull()
			.hasSize(1);
	}

	@Test
	@DisplayName("should fail to select any JWK from keyset")
	void shouldNotSelectAnyKey() throws IOException {
		final var keyset = (JsonWebKeyset) generate("selecting-keyset", JoseAlgorithm.HS256);

		final var selector = new JWKSelector(
			new JWKMatcher.Builder()
				.keyOperation(KeyOperation.ENCRYPT)
				.build()
		);

		assertThat(keyset.get(selector, null))
			.isNotNull()
			.isEmpty();
	}

	@Test
	@DisplayName("should rotate keyset")
	void shouldRotateKeyset() throws IOException {
		final var keyset = generate("rotating-keyset", JoseAlgorithm.HS256);
		final var rotated = keyset.rotate();

		assertThatObject(rotated)
			.isNotNull()
				.isNotEqualTo(keyset)
				.isInstanceOf(JsonWebKeyset.class)
				.returns(keyset.getName(), Keyset::getName)
				.returns(keyset.getAlgorithm(), Keyset::getAlgorithm)
				.returns(keyset.getKeyEncryptionKey(), Keyset::getKeyEncryptionKey)
				.returns(keyset.getRotationInterval(), Keyset::getRotationInterval)
				.satisfies(it -> assertThat(it.getNextRotationTime())
					.isAfter(keyset.getNextRotationTime())
					.isCloseTo(Instant.now().plus(it.getRotationInterval()), within(1, ChronoUnit.SECONDS))
				);

		assertThat(rotated.getKeys())
			.hasSize(2)
			.asInstanceOf(InstanceOfAssertFactories.iterable(JsonWebKey.class))
			.extracting(Key::getType, Key::getStatus, Key::isPrimary, it -> it.getValue().getKeyOperations())
			.containsExactlyInAnyOrder(
				tuple(KeyType.OCTET, KeyStatus.ENABLED, true, Set.of(KeyOperation.SIGN, KeyOperation.VERIFY)),
				tuple(KeyType.OCTET, KeyStatus.ENABLED, false, Set.of(KeyOperation.VERIFY))
			);

		assertThat(rotated.rotate())
			.hasSize(3)
			.asInstanceOf(InstanceOfAssertFactories.iterable(JsonWebKey.class))
			.extracting(Key::getType, Key::getStatus, Key::isPrimary, it -> it.getValue().getKeyOperations())
			.containsExactlyInAnyOrder(
				tuple(KeyType.OCTET, KeyStatus.ENABLED, true, Set.of(KeyOperation.SIGN, KeyOperation.VERIFY)),
				tuple(KeyType.OCTET, KeyStatus.ENABLED, false, Set.of(KeyOperation.VERIFY)),
				tuple(KeyType.OCTET, KeyStatus.ENABLED, false, Set.of(KeyOperation.VERIFY))
			);

		assertThat(rotated.getKeys())
			.filteredOn(Key::isPrimary, false)
			.hasSize(1)
			.first()
			.returns(keyset.getKeys().get(0).getId(), Key::getId)
			.returns(false, Key::isPrimary);

	}

	@Test
	@DisplayName("should throw unsupported operation when encrypting data")
	void unsupportedEncryptOperation() throws IOException {
		final var key = generate("signing-keyset", JoseAlgorithm.HS256);

		assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
			.isThrownBy(() -> key.encrypt(ByteArray.fromString("data to be encrypted")))
			.returns(KeysetOperation.ENCRYPT, CryptoException.KeysetOperationException::attemptedOperation)
			.returns(key.getAlgorithm().operations(), CryptoException.UnsupportedKeysetOperationException::supportedOperations);
	}

	@Test
	@DisplayName("should throw unsupported operation when decrypting data")
	void unsupportedDecryptOperation() throws IOException {
		final var key = generate("signing-keyset", JoseAlgorithm.HS256);

		assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
			.isThrownBy(() -> key.decrypt(ByteArray.fromString("data to be decrypted")))
			.returns(KeysetOperation.DECRYPT, CryptoException.KeysetOperationException::attemptedOperation)
			.returns(key.getAlgorithm().operations(), CryptoException.UnsupportedKeysetOperationException::supportedOperations);
	}

	@Test
	@DisplayName("should throw unsupported operation when signing data")
	void unsupportedSignOperation() throws IOException {
		final var key = generate("encrypting-keyset", JoseAlgorithm.A128KW);

		assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
			.isThrownBy(() -> key.sign(ByteArray.fromString("data to be signed")))
			.returns(KeysetOperation.SIGN, CryptoException.KeysetOperationException::attemptedOperation)
			.returns(key.getAlgorithm().operations(), CryptoException.UnsupportedKeysetOperationException::supportedOperations);
	}

	@Test
	@DisplayName("should throw unsupported operation when verifying signature")
	void unsupportedVerifyOperation() throws IOException {
		final var key = generate("encrypting-keyset", JoseAlgorithm.A128KW);

		assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
			.isThrownBy(() -> key.verify(ByteArray.fromString("jws"), ByteArray.fromString("data")))
			.returns(KeysetOperation.VERIFY, CryptoException.KeysetOperationException::attemptedOperation)
			.returns(key.getAlgorithm().operations(), CryptoException.UnsupportedKeysetOperationException::supportedOperations);
	}

	@Test
	@DisplayName("should fail to decrypt invalid JWE data")
	void decryptInvalidJWE() throws IOException {
		final var key = generate("encrypting-keyset", JoseAlgorithm.A128KW);

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.isThrownBy(() -> key.decrypt(ByteArray.fromString("data to be encrypted")))
			.returns(KeysetOperation.DECRYPT, CryptoException.KeysetOperationException::attemptedOperation)
			.withRootCauseInstanceOf(ParseException.class);
	}

	@Test
	@DisplayName("should fail to decrypt JWE encrypted by a different keyset with same algorithm")
	void decryptJWEFromDifferentKeyset() throws IOException {
		final var encrypting = generate("encrypting-keyset", JoseAlgorithm.A128KW);
		final var decrypting = generate("decrypting-keyset", JoseAlgorithm.A128KW);

		final var jwe = encrypting.encrypt(ByteArray.fromString("data to be encrypted"));

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.isThrownBy(() -> decrypting.decrypt(jwe))
			.returns(KeysetOperation.DECRYPT, CryptoException.KeysetOperationException::attemptedOperation)
			.withRootCauseInstanceOf(KeySourceException.class)
			.havingRootCause()
			.withMessageContaining("No matching key found for JWK matcher");
	}

	@Test
	@DisplayName("should fail to verify invalid JWS data")
	void verifyInvalidJWS() throws IOException {
		final var key = generate("signing-keyset", JoseAlgorithm.HS256);

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.isThrownBy(() -> key.verify(ByteArray.fromString("jws"), ByteArray.fromString("data to be verified")))
			.returns(KeysetOperation.VERIFY, CryptoException.KeysetOperationException::attemptedOperation)
			.withRootCauseInstanceOf(ParseException.class);
	}

	@Test
	@DisplayName("should fail to verify JWS signed by a different keyset with same algorithm")
	void verifyJWSFromDifferentKeyset() throws IOException {
		final var signing = generate("signing-keyset", JoseAlgorithm.HS256);
		final var verifier = generate("verifying-keyset", JoseAlgorithm.HS256);

		final var jws = signing.sign(ByteArray.fromString("data to be signed"));

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.isThrownBy(() -> verifier.verify(jws, ByteArray.fromString("data to be signed")))
			.returns(KeysetOperation.VERIFY, CryptoException.KeysetOperationException::attemptedOperation)
			.withRootCauseInstanceOf(KeySourceException.class)
			.havingRootCause()
			.withMessageContaining("No matching key found for JWK matcher");
	}

	@Test
	@DisplayName("should fail to verify JWS with different signing inputs")
	void verifyJWSFromDifferentInputs() throws IOException {
		final var key = generate("signing-keyset", JoseAlgorithm.HS256);
		final var jws = key.sign(ByteArray.fromString("data to be signed"));

		assertThat(key.verify(jws, ByteArray.fromString("different input")))
			.isFalse();
	}

	@Test
	@DisplayName("should have a toString representation")
	void shouldHaveToStringRepresentation() throws IOException {
		final var key = generate("keyset", JoseAlgorithm.HS256);

		assertThat(key)
			.hasToString(
				"JsonWebKeyset[name='%s', algorithm=%s, keys=%s, keyEncryptionKey=%s, rotationInterval=%s, nextRotationTime=%s]",
				key.getName(), key.getAlgorithm(), key.getKeys(), key.getKeyEncryptionKey(), key.getRotationInterval(), key.getNextRotationTime()
			);
	}

	@Test
	@DisplayName("JSON web keysets should be unique")
	void shouldCheckKeysetEquality() throws IOException {
		final var key = generate("keyset", JoseAlgorithm.HS256);
		final var rotated = key.rotate();

		assertThat(key)
			.isNotEqualTo(rotated)
			.doesNotHaveSameHashCodeAs(rotated)
			.isNotEqualTo(generate("keyset", JoseAlgorithm.HS256))
			.doesNotHaveSameHashCodeAs(generate("keyset", JoseAlgorithm.HS256));
	}

	static Stream<Arguments> signingAlgorithms() {
		return Arrays.stream(JoseAlgorithm.values())
			.filter(algorithm -> algorithm.supports(KeysetOperation.SIGN))
			.map(Arguments::of);
	}

	static Stream<Arguments> encryptionAlgorithms() {
		return Arrays.stream(JoseAlgorithm.values())
			.filter(algorithm -> algorithm.supports(KeysetOperation.ENCRYPT))
			.map(Arguments::of);
	}

}
