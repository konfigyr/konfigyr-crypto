package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.KeyEncryptionKeyProvider;
import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetOperation;
import com.konfigyr.crypto.KeysetStore;
import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

class X509MaterialSelectorTest {

	X509Keyset keyset;
	X509Key primary;
	X509Key next;
	X509Key retired;

	@BeforeEach
	void setup() {
		final X509Keyset initial = X509KeysetTest.keyset(X509Algorithm.RSA_3072_SIGNING);

		// initial key is retired, a new primary is created, followed by a non-primary next key
		final X509Keyset rotated = (X509Keyset) initial.rotate();
		keyset = (X509Keyset) rotated.rotate(KeyDefinition.builder()
			.algorithm(X509Algorithm.EC_P256_SIGNING)
			.primary(false)
			.build());

		primary = (X509Key) keyset.getPrimary();
		retired = keyset.getKey(initial.getPrimary().getId()).orElseThrow();
		next = keyset.getKeys().stream()
			.filter(key -> key != primary && key != retired)
			.findFirst()
			.orElseThrow();
	}

	@Test
	@DisplayName("should expose keyset keys as X509 material")
	void shouldExposeKeysAsMaterial() {
		assertThat(keyset.getKeys())
			.hasSize(3)
			.allSatisfy(key -> assertThat(key).isInstanceOf(X509Material.class));
	}

	@Test
	@DisplayName("should select all usable keys with the primary key first, followed by the newest keys")
	void shouldSelectInOrder() {
		assertThat(keyset.select(X509Matcher.any()))
			.extracting(X509Material::getId)
			.containsExactly(primary.getId(), next.getId(), retired.getId());
	}

	@Test
	@DisplayName("should select keys that match all of the matcher criteria")
	void shouldSelectMatchingKeys() {
		assertThat(keyset.select(X509Matcher.builder().primary(true).build()))
			.containsExactly(primary);

		assertThat(keyset.select(X509Matcher.builder().primary(false).build()))
			.containsExactly(next, retired);

		assertThat(keyset.select(X509Matcher.builder().keyTypes(KeyType.EC).build()))
			.containsExactly(next);

		assertThat(keyset.select(X509Matcher.builder().algorithms(X509Algorithm.RSA_3072_SIGNING).build()))
			.containsExactly(primary, retired);

		assertThat(keyset.select(X509Matcher.builder().keyIds(retired.getId(), UUID.randomUUID().toString()).build()))
			.containsExactly(retired);

		assertThat(keyset.select(X509Matcher.builder().primary(true).keyTypes(KeyType.EC).build()))
			.isEmpty();
	}

	@Test
	@DisplayName("should select keys by certificate validity")
	void shouldSelectByValidity() {
		assertThat(keyset.select(X509Matcher.builder().validAt(Instant.now()).build()))
			.hasSize(3);

		assertThat(keyset.select(X509Matcher.builder().validAt(Instant.now().minus(1, ChronoUnit.DAYS)).build()))
			.as("certificates must not be valid before the keys were created")
			.isEmpty();
	}

	@EnumSource(value = KeyStatus.class, names = { "ENABLED", "RETIRED" }, mode = EnumSource.Mode.EXCLUDE)
	@ParameterizedTest(name = "status: {0}")
	@DisplayName("should never select keys that are not enabled or retired, even when the matcher matches them")
	void shouldNeverSelectBlockedKeys(KeyStatus status) {
		final X509Keyset blocked = withStatus(withStatus(keyset, retired, status), next, status);

		assertThat(blocked.select(X509Matcher.any()))
			.extracting(X509Material::getId)
			.containsExactly(primary.getId());

		assertThat(blocked.select(X509Matcher.builder().keyIds(retired.getId(), next.getId()).build()))
			.isEmpty();

		assertThat(withStatus(blocked, primary, status).select(X509Matcher.any()))
			.as("a primary key that is not enabled must not be selected either")
			.isEmpty();
	}

	@Test
	@DisplayName("should select retired keys after the primary key")
	void shouldSelectRetiredKeys() {
		final X509Keyset withRetired = withStatus(keyset, retired, KeyStatus.RETIRED);

		assertThat(withRetired.select(X509Matcher.any()))
			.extracting(X509Material::getId)
			.first()
			.isEqualTo(primary.getId());

		assertThat(withRetired.select(X509Matcher.builder().keyIds(retired.getId()).build()))
			.singleElement()
			.returns(KeyStatus.RETIRED, X509Material::getStatus);
	}

	@Test
	@DisplayName("should only select the enabled primary key of a signing keyset to sign")
	void shouldSelectSigningKey() {
		final X509Keyset withRetired = withStatus(keyset, retired, KeyStatus.RETIRED);

		assertThat(withRetired.select(X509Matcher.builder().operations(KeysetOperation.SIGN).build()))
			.containsExactly(primary);

		assertThat(withRetired.select(X509Matcher.builder().operations(KeysetOperation.SIGN).keyTypes(KeyType.EC).build()))
			.as("other criteria must still narrow down the selection")
			.isEmpty();
	}

	@Test
	@DisplayName("should select the enabled and retired keys of a signing keyset to verify")
	void shouldSelectVerificationKeys() {
		final X509Keyset withRetired = withStatus(keyset, retired, KeyStatus.RETIRED);

		assertThat(withRetired.select(X509Matcher.builder().operations(KeysetOperation.VERIFY).build()))
			.extracting(X509Material::getId)
			.containsExactly(primary.getId(), next.getId(), retired.getId());

		assertThat(withRetired.select(X509Matcher.builder().operations(KeysetOperation.SIGN, KeysetOperation.VERIFY).build()))
			.as("keys that may perform any of the operations must be selected")
			.extracting(X509Material::getId)
			.containsExactly(primary.getId(), next.getId(), retired.getId());
	}

	@Test
	@DisplayName("should not select keys of a signing keyset to encrypt or decrypt")
	void shouldNotSelectSigningKeysForEncryption() {
		assertThat(keyset.select(X509Matcher.builder().operations(KeysetOperation.ENCRYPT, KeysetOperation.DECRYPT).build()))
			.isEmpty();
	}

	@EnumSource(value = KeyStatus.class, names = "ENABLED", mode = EnumSource.Mode.EXCLUDE)
	@ParameterizedTest(name = "status: {0}")
	@DisplayName("should not select a primary key that is not enabled to sign")
	void shouldNotSelectBlockedSigningKey(KeyStatus status) {
		final X509Keyset blocked = withStatus(keyset, primary, status);

		assertThat(blocked.select(X509Matcher.builder().operations(KeysetOperation.SIGN).build()))
			.isEmpty();
	}

	@Test
	@DisplayName("should select the enabled and retired keys of an encryption keyset to decrypt, and only the primary key to encrypt")
	void shouldSelectEncryptionKeys() {
		final EncryptionKeyset encryption = EncryptionKeyset.create();

		assertThat(encryption.keyset().select(X509Matcher.builder().operations(KeysetOperation.DECRYPT).build()))
			.extracting(X509Material::getId)
			.containsExactly(encryption.primary().getId(), encryption.next().getId(), encryption.retired().getId());

		assertThat(encryption.keyset().select(X509Matcher.builder().operations(KeysetOperation.ENCRYPT).build()))
			.extracting(X509Material::getId)
			.containsExactly(encryption.primary().getId());

		assertThat(encryption.keyset().select(X509Matcher.builder().operations(KeysetOperation.SIGN, KeysetOperation.VERIFY).build()))
			.isEmpty();
	}

	@Test
	@DisplayName("should select enabled keys, which excludes retired keys, or only the retired keys")
	void shouldSelectEnabledKeys() {
		final X509Keyset withRetired = withStatus(keyset, retired, KeyStatus.RETIRED);

		assertThat(withRetired.select(X509Matcher.builder().enabled(true).build()))
			.extracting(X509Material::getId)
			.containsExactly(primary.getId(), next.getId());

		assertThat(withRetired.select(X509Matcher.builder().enabled(false).build()))
			.extracting(X509Material::getId)
			.containsExactly(retired.getId());

		assertThat(withRetired.select(X509Matcher.builder().enabled(null).build()))
			.extracting(X509Material::getId)
			.containsExactly(primary.getId(), next.getId(), retired.getId());
	}

	@Test
	@DisplayName("should select the decryption keys and the published certificates of an encryption keyset, as documented in the X509Matcher")
	void shouldSelectPublishedEncryptionKeys() {
		final EncryptionKeyset encryption = EncryptionKeyset.create();

		assertThat(encryption.keyset().select(X509Matcher.builder()
				.operations(KeysetOperation.DECRYPT)
				.build()))
			.as("decryption credentials must include retired keys")
			.extracting(X509Material::getId)
			.containsExactly(encryption.primary().getId(), encryption.next().getId(), encryption.retired().getId());

		assertThat(encryption.keyset().select(X509Matcher.builder()
				.operations(KeysetOperation.DECRYPT)
				.enabled(true)
				.build()))
			.as("published certificates must not include retired keys")
			.extracting(X509Material::getId)
			.containsExactly(encryption.primary().getId(), encryption.next().getId());
	}

	@Test
	@DisplayName("should reject null operations")
	void shouldRejectNullOperations() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> X509Matcher.builder().operations(KeysetOperation.SIGN, null));
	}

	@Test
	@DisplayName("should hand over the private key of the primary key to sign")
	void shouldConvertPrivateKey() throws Exception {
		final X509Material material = keyset.select(X509Matcher.builder().operations(KeysetOperation.SIGN).build()).getFirst();
		final ByteArray data = ByteArray.fromString("konfigyr-crypto-x509-data");

		final byte[] signature = material.convert(KeysetOperation.SIGN, privateKey -> sign(privateKey, data));

		final Signature verifier = Signature.getInstance(X509Algorithm.RSA_3072_SIGNING.signatureAlgorithm());
		verifier.initVerify(material.getCertificate());
		verifier.update(data.array());

		assertThat(verifier.verify(signature))
			.as("private key must match the public key of the certificate")
			.isTrue();
	}

	@EnumSource(value = KeyStatus.class, names = "ENABLED", mode = EnumSource.Mode.EXCLUDE)
	@ParameterizedTest(name = "status: {0}")
	@DisplayName("should not hand over the private key of a primary key that is not enabled to sign")
	void shouldNotConvertBlockedSigningKey(KeyStatus status) {
		final X509Material material = new X509Key.Builder(primary).status(status).build();

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.isThrownBy(() -> material.convert(KeysetOperation.SIGN, PrivateKey::getAlgorithm))
			.withMessage("X509 key '%s' is %s and its private key material can not be used to SIGN.", primary.getId(), status)
			.returns(KeysetOperation.SIGN, CryptoException.KeysetOperationException::attemptedOperation);
	}

	@Test
	@DisplayName("should not hand over the private key of an enabled key that is not the primary key to sign")
	void shouldNotConvertNextKeyToSign() {
		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.isThrownBy(() -> next.convert(KeysetOperation.SIGN, PrivateKey::getAlgorithm))
			.withMessage("X509 key '%s' is not the primary key and its private key material can not be used to SIGN.",
				next.getId());
	}

	@EnumSource(value = KeyStatus.class, names = { "ENABLED", "RETIRED" }, mode = EnumSource.Mode.EXCLUDE)
	@ParameterizedTest(name = "status: {0}")
	@DisplayName("should not hand over the private key of keys that are not enabled or retired to decrypt")
	void shouldNotConvertBlockedDecryptionKeys(KeyStatus status) {
		final EncryptionKeyset encryption = EncryptionKeyset.create();
		final X509Material material = new X509Key.Builder(encryption.retired()).status(status).build();

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.isThrownBy(() -> material.convert(KeysetOperation.DECRYPT, PrivateKey::getAlgorithm))
			.withMessage("X509 key '%s' is %s and its private key material can not be used to DECRYPT.",
				encryption.retired().getId(), status);
	}

	@Test
	@DisplayName("should hand over the private key of enabled and retired keys to decrypt")
	void shouldConvertDecryptionKeys() {
		final EncryptionKeyset encryption = EncryptionKeyset.create();

		assertThat(encryption.keyset().select(X509Matcher.builder().operations(KeysetOperation.DECRYPT).build()))
			.hasSize(3)
			.allSatisfy(material -> assertThat(material.<String>convert(KeysetOperation.DECRYPT, PrivateKey::getAlgorithm))
				.isEqualTo(material.getPublicKey().getAlgorithm()));
	}

	@Test
	@DisplayName("should not hand over the private key of a retired key to sign")
	void shouldNotConvertRetiredKeyToSign() {
		final X509Material material = new X509Key.Builder(retired).status(KeyStatus.RETIRED).build();

		assertThatExceptionOfType(CryptoException.KeysetOperationException.class)
			.isThrownBy(() -> material.convert(KeysetOperation.SIGN, PrivateKey::getAlgorithm))
			.withMessage("X509 key '%s' is RETIRED and its private key material can not be used to SIGN.", retired.getId());
	}

	@Test
	@DisplayName("should not hand over the private key for operations that are not supported by the key purpose")
	void shouldNotConvertForUnsupportedOperations() {
		assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
			.isThrownBy(() -> primary.convert(KeysetOperation.DECRYPT, PrivateKey::getAlgorithm))
			.returns(KeysetOperation.DECRYPT, CryptoException.KeysetOperationException::attemptedOperation);

		final EncryptionKeyset encryption = EncryptionKeyset.create();

		assertThatExceptionOfType(CryptoException.UnsupportedKeysetOperationException.class)
			.isThrownBy(() -> encryption.primary().convert(KeysetOperation.SIGN, PrivateKey::getAlgorithm))
			.returns(KeysetOperation.SIGN, CryptoException.KeysetOperationException::attemptedOperation);
	}

	@EnumSource(value = KeysetOperation.class, names = { "VERIFY", "ENCRYPT" })
	@ParameterizedTest(name = "operation: {0}")
	@DisplayName("should not hand over the private key for operations that use the public key")
	void shouldNotConvertForPublicKeyOperations(KeysetOperation operation) {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> primary.convert(operation, PrivateKey::getAlgorithm))
			.withMessage("The %s operation does not use the private key, use the public key or the certificate instead",
				operation);
	}

	@Test
	@DisplayName("should reject a null private key operation or converter")
	void shouldRejectNullConverter() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> primary.convert(null, PrivateKey::getAlgorithm));

		assertThatIllegalArgumentException()
			.isThrownBy(() -> primary.convert(KeysetOperation.SIGN, null));
	}

	@Test
	@DisplayName("should select X509 credentials from a keyset read from the keyset store, as documented in the X509MaterialSelector")
	void shouldSelectFromKeysetStore() {
		final KeyEncryptionKey kek = TestKeyEncryptionKey.INSTANCE;
		final KeysetStore store = KeysetStore.builder()
			.factories(X509KeysetFactoryTest.createFactory())
			.providers(KeyEncryptionKeyProvider.of(kek.getProvider(), kek))
			.build();

		store.create(kek.getProvider(), kek.getId(), KeysetDefinition.of(
			"saml-signing", X509Algorithm.RSA_3072_SIGNING
		));

		final Keyset keyset = store.read("saml-signing");

		assertThat(keyset)
			.isInstanceOf(X509MaterialSelector.class);

		final X509MaterialSelector selector = (X509MaterialSelector) keyset;

		// mirrors the X509MaterialSelector example, using a credential record instead of the Spring Security type
		final X509Material primary = selector.select(X509Matcher.builder()
				.operations(KeysetOperation.SIGN)
				.build())
			.getFirst();

		final Credential signing = primary.convert(KeysetOperation.SIGN,
			privateKey -> new Credential(privateKey, primary.getCertificate())
		);

		final List<X509Certificate> certificates = selector.select(X509Matcher.builder()
				.enabled(true)
				.validAt(Instant.now())
				.build())
			.stream()
			.map(X509Material::getCertificate)
			.toList();

		assertThat(certificates)
			.containsExactly(primary.getCertificate());

		assertThat(signing)
			.satisfies(credential -> {
				assertThat(credential.certificate())
					.isEqualTo(((X509Material) keyset.getPrimary()).getCertificate())
					.returns("CN=saml-signing", certificate -> certificate.getSubjectX500Principal().getName());

				final ByteArray data = ByteArray.fromString("konfigyr-crypto-x509-data");
				final Signature verifier = Signature.getInstance(X509Algorithm.RSA_3072_SIGNING.signatureAlgorithm());
				verifier.initVerify(credential.certificate());
				verifier.update(data.array());

				assertThat(verifier.verify(sign(credential.privateKey(), data)))
					.as("credential private key must match its certificate")
					.isTrue();
			});
	}

	record Credential(PrivateKey privateKey, X509Certificate certificate) {
	}

	@Test
	@DisplayName("should not expose private key material through toString")
	void shouldNotExposePrivateKeyInToString() {
		final String encoded = new ByteArray(primary.privateKey().getEncoded()).encodeBase64();

		assertThat(keyset.select(X509Matcher.any()).toString())
			.doesNotContain(encoded);
	}

	/**
	 * Encryption keyset with a primary key, a next key that is not yet the primary key, and a retired key.
	 */
	record EncryptionKeyset(X509Keyset keyset, X509Key primary, X509Key next, X509Key retired) {

		static EncryptionKeyset create() {
			final X509Keyset initial = X509KeysetTest.keyset(X509Algorithm.RSA_3072_ENCRYPTION);
			final X509Keyset rotated = (X509Keyset) ((X509Keyset) initial.rotate()).rotate(KeyDefinition.builder()
				.algorithm(X509Algorithm.RSA_3072_ENCRYPTION)
				.primary(false)
				.build());

			final String retiredId = initial.getPrimary().getId();
			final X509Keyset keyset = withStatus(rotated, (X509Key) rotated.getKey(retiredId).orElseThrow(), KeyStatus.RETIRED);

			final X509Key primary = (X509Key) keyset.getPrimary();
			final X509Key retired = (X509Key) keyset.getKey(retiredId).orElseThrow();
			final X509Key next = keyset.getKeys().stream()
				.filter(key -> !key.getId().equals(primary.getId()) && !key.getId().equals(retiredId))
				.findFirst()
				.orElseThrow();

			return new EncryptionKeyset(keyset, primary, next, retired);
		}

	}

	static X509Keyset withStatus(X509Keyset keyset, X509Key target, KeyStatus status) {
		final X509Keyset.Builder builder = new X509Keyset.Builder(keyset);

		keyset.getKeys().forEach(key -> builder.key(key.getId().equals(target.getId())
			? new X509Key.Builder(key).status(status).build()
			: key));

		return builder.build();
	}

	static byte[] sign(PrivateKey privateKey, ByteArray data) {
		try {
			final Signature signature = Signature.getInstance(X509Algorithm.RSA_3072_SIGNING.signatureAlgorithm());
			signature.initSign(privateKey);
			signature.update(data.array());
			return signature.sign();
		} catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

}
