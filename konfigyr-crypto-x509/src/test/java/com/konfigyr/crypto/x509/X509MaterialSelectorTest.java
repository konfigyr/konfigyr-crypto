package com.konfigyr.crypto.x509;

import com.konfigyr.crypto.CryptoException;
import com.konfigyr.crypto.KeyDefinition;
import com.konfigyr.crypto.KeyEncryptionKey;
import com.konfigyr.crypto.KeyEncryptionKeyProvider;
import com.konfigyr.crypto.KeyStatus;
import com.konfigyr.crypto.KeyType;
import com.konfigyr.crypto.Keyset;
import com.konfigyr.crypto.KeysetDefinition;
import com.konfigyr.crypto.KeysetStore;
import com.konfigyr.crypto.test.TestKeyEncryptionKey;
import com.konfigyr.io.ByteArray;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

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
		retired = (X509Key) keyset.getKey(initial.getPrimary().getId()).orElseThrow();
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
	@DisplayName("should select keys by status and certificate validity")
	void shouldSelectByStatusAndValidity() {
		final X509Keyset disabled = withStatus(keyset, retired, KeyStatus.DISABLED);

		assertThat(disabled.select(X509Matcher.builder().statuses(KeyStatus.ENABLED).build()))
			.extracting(X509Material::getId)
			.containsExactly(primary.getId(), next.getId());

		assertThat(disabled.select(X509Matcher.builder().statuses(KeyStatus.DISABLED).build()))
			.extracting(X509Material::getId)
			.containsExactly(retired.getId());

		assertThat(keyset.select(X509Matcher.builder().validAt(Instant.now()).build()))
			.hasSize(3);

		assertThat(keyset.select(X509Matcher.builder().validAt(Instant.now().minus(1, ChronoUnit.DAYS)).build()))
			.as("certificates must not be valid before the keys were created")
			.isEmpty();
	}

	@Test
	@DisplayName("should never select compromised or destroyed keys, even when the matcher asks for them")
	void shouldNeverSelectUnusableKeys() {
		final X509Keyset unusable = withStatus(withStatus(keyset, retired, KeyStatus.COMPROMISED),
			next, KeyStatus.DESTROYED);

		assertThat(unusable.select(X509Matcher.any()))
			.extracting(X509Material::getId)
			.containsExactly(primary.getId());

		assertThat(unusable.select(X509Matcher.builder()
				.statuses(KeyStatus.COMPROMISED, KeyStatus.DESTROYED)
				.build()))
			.isEmpty();
	}

	@Test
	@DisplayName("should hand over the private key that matches the certificate")
	void shouldConvertPrivateKey() throws Exception {
		final X509Material material = keyset.select(X509Matcher.builder().primary(true).build()).getFirst();
		final ByteArray data = ByteArray.fromString("konfigyr-crypto-x509-data");

		final byte[] signature = material.convert(privateKey -> sign(privateKey, data));

		final Signature verifier = Signature.getInstance(X509Algorithm.RSA_3072_SIGNING.signatureAlgorithm());
		verifier.initVerify(material.getCertificate());
		verifier.update(data.array());

		assertThat(verifier.verify(signature))
			.as("private key must match the public key of the certificate")
			.isTrue();
	}

	@Test
	@DisplayName("should not hand over the private key of compromised or destroyed keys")
	void shouldNotConvertUnusableKeys() {
		final X509Material compromised = new X509Key.Builder(retired).status(KeyStatus.COMPROMISED).build();
		final X509Material destroyed = new X509Key.Builder(retired).status(KeyStatus.DESTROYED).build();

		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.isThrownBy(() -> compromised.convert(PrivateKey::getAlgorithm))
			.withMessage("X509 key '%s' is COMPROMISED and its private key material can not be used.", retired.getId());

		assertThatExceptionOfType(CryptoException.KeysetException.class)
			.isThrownBy(() -> destroyed.convert(PrivateKey::getAlgorithm))
			.withMessage("X509 key '%s' is DESTROYED and its private key material can not be used.", retired.getId());

		assertThatIllegalArgumentException()
			.isThrownBy(() -> primary.convert(null));
	}

	@Test
	@DisplayName("should select X509 credentials from a keyset read from the keyset store, as documented in the README")
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

		// mirrors the README example, using a credential record instead of the Spring Security type
		final List<Credential> credentials = selector.select(X509Matcher.builder().statuses(KeyStatus.ENABLED).build())
			.stream()
			.map(material -> material.convert(
				privateKey -> new Credential(privateKey, material.getCertificate())
			))
			.toList();

		assertThat(credentials)
			.hasSize(1)
			.first()
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
