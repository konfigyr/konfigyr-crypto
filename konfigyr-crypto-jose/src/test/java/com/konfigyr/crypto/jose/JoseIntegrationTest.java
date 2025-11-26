package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.*;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static com.konfigyr.crypto.jose.JoseIntegrationConfiguration.KEK_IDENTIFIER;
import static com.konfigyr.crypto.jose.JoseIntegrationConfiguration.KEK_PROVIDER;
import static org.assertj.core.api.Assertions.*;

@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@SpringBootTest(classes = JoseIntegrationConfiguration.class)
public class JoseIntegrationTest {

	static final KeysetDefinition jweDefinition = KeysetDefinition.of("jose-jwe-keyset", JoseAlgorithm.A128KW);
	static final KeysetDefinition jwsDefinition = KeysetDefinition.of("jose-jws-keyset", JoseAlgorithm.PS256);

	@Autowired
	KeysetStore store;

	@Test
	@Order(1)
	@DisplayName("should retrieve configured key encryption key providers")
	void shouldRetrieveProviders() {
		assertThat(store.provider(KEK_PROVIDER))
			.isPresent()
			.get()
			.extracting(provider -> provider.provide(KEK_IDENTIFIER))
			.isNotNull();

		assertThat(store.provider("unknown-provider")).isEmpty();
	}

	@Test
	@Order(2)
	@DisplayName("should generate keyset using supported JOSE signing algorithm")
	void shouldGenerateSigningKeyset() {
		final var kek = store.kek(KEK_PROVIDER, KEK_IDENTIFIER);

		assertThatObject(store.create(kek, jwsDefinition))
			.isInstanceOf(JsonWebKeyset.class)
			.returns(jwsDefinition.getName(), Keyset::getName)
			.returns(jwsDefinition.getAlgorithm(), Keyset::getAlgorithm)
			.returns(kek, Keyset::getKeyEncryptionKey)
			.returns(jwsDefinition.getRotationInterval(), Keyset::getRotationInterval)
			.returns(jwsDefinition.getNextRotationTime(), Keyset::getNextRotationTime)
			.satisfies(it -> assertThat(it.getKeys())
				.isNotNull()
				.hasSize(1)
				.extracting(Key::getType, Key::getStatus, Key::isPrimary)
				.containsExactly(tuple(KeyType.RSA, KeyStatus.ENABLED, true))
			);
	}

	@Test
	@Order(3)
	@DisplayName("should generate keyset using supported JOSE encryption algorithm")
	void shouldGenerateEncryptingKeyset() {
		final var kek = store.kek(KEK_PROVIDER, KEK_IDENTIFIER);

		assertThatObject(store.create(kek, jweDefinition))
			.isInstanceOf(JsonWebKeyset.class)
			.returns(jweDefinition.getName(), Keyset::getName)
			.returns(jweDefinition.getAlgorithm(), Keyset::getAlgorithm)
			.returns(kek, Keyset::getKeyEncryptionKey)
			.returns(jweDefinition.getRotationInterval(), Keyset::getRotationInterval)
			.returns(jweDefinition.getNextRotationTime(), Keyset::getNextRotationTime)
			.satisfies(it -> assertThat(it.getKeys())
				.isNotNull()
				.hasSize(1)
				.extracting(Key::getType, Key::getStatus, Key::isPrimary)
				.containsExactly(tuple(KeyType.OCTET, KeyStatus.ENABLED, true))
			);
	}

	@Test
	@Order(3)
	@DisplayName("should wrap and write keyset in the repository")
	void shouldWriteKeyset() throws Exception {
		final var jwk = new OctetSequenceKeyGenerator(128)
			.keyID("test-id")
			.generate();

		final var primary = new JsonWebKey(jwk, KeyStatus.ENABLED, true);

		final var keyset = JsonWebKeyset.builder(List.of(primary))
			.name("simple-keyset")
			.algorithm(JoseAlgorithm.A128KW)
			.keyEncryptionKey(store.kek(KEK_PROVIDER, KEK_IDENTIFIER))
			.rotationInterval(Duration.ofDays(180))
			.nextRotationTime(Instant.now().plus(Duration.ofDays(180)))
			.build();

		assertThatNoException().isThrownBy(() -> store.write(keyset));

		assertThatObject(store.read(keyset.getName()))
			.isEqualTo(keyset);
	}

	@Test
	@Order(4)
	@DisplayName("should read and unwrap JWS keyset from the repository")
	void shouldReadSigningKeyset() {
		final var kek = store.kek(KEK_PROVIDER, KEK_IDENTIFIER);

		assertThatObject(store.read(jwsDefinition.getName()))
			.isInstanceOf(JsonWebKeyset.class)
			.returns(jwsDefinition.getName(), Keyset::getName)
			.returns(jwsDefinition.getAlgorithm(), Keyset::getAlgorithm)
			.returns(kek, Keyset::getKeyEncryptionKey)
			.returns(jwsDefinition.getRotationInterval(), Keyset::getRotationInterval)
			.returns(jwsDefinition.getNextRotationTime(), Keyset::getNextRotationTime)
			.satisfies(it -> assertThat(it.getKeys())
				.isNotNull()
				.hasSize(1)
				.extracting(Key::getType, Key::getStatus, Key::isPrimary)
				.containsExactly(tuple(KeyType.RSA, KeyStatus.ENABLED, true))
			);
	}

	@Test
	@Order(4)
	@DisplayName("should read and unwrap JWE keyset from the repository")
	void shouldReadEncryptingKeyset() {
		final var kek = store.kek(KEK_PROVIDER, KEK_IDENTIFIER);

		assertThatObject(store.read(jweDefinition.getName()))
			.isInstanceOf(JsonWebKeyset.class)
			.returns(jweDefinition.getName(), Keyset::getName)
			.returns(jweDefinition.getAlgorithm(), Keyset::getAlgorithm)
			.returns(kek, Keyset::getKeyEncryptionKey)
			.returns(jweDefinition.getRotationInterval(), Keyset::getRotationInterval)
			.returns(jweDefinition.getNextRotationTime(), Keyset::getNextRotationTime)
			.satisfies(it -> assertThat(it.getKeys())
				.isNotNull()
				.hasSize(1)
				.extracting(Key::getType, Key::getStatus, Key::isPrimary)
				.containsExactly(tuple(KeyType.OCTET, KeyStatus.ENABLED, true))
			);
	}

	@Test
	@Order(5)
	@DisplayName("should rotate JOSE keyset and store it in the repository")
	void shouldRotateKeyset() {
		final var keyset = store.read(jwsDefinition.getName());

		assertThatObject(keyset)
			.returns(1, Keyset::size);

		assertThatNoException().isThrownBy(() -> store.rotate(keyset));

		assertThatObject(store.read(jwsDefinition.getName()))
			.isNotEqualTo(keyset)
			.returns(2, Keyset::size);
	}

	@Test
	@Order(6)
	@DisplayName("should remove keyset from the repository")
	void shouldRemoveKeyset() {
		assertThatNoException().isThrownBy(() -> store.remove(jwsDefinition.getName()));

		assertThatExceptionOfType(CryptoException.KeysetNotFoundException.class)
			.isThrownBy(() -> store.read(jwsDefinition.getName()));
	}

}
