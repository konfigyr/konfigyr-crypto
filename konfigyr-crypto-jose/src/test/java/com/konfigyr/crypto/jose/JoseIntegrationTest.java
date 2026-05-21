package com.konfigyr.crypto.jose;

import com.konfigyr.crypto.*;
import com.konfigyr.crypto.test.KeysetAssert;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

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

		KeysetAssert.assertThat(store.create(kek, jwsDefinition))
			.isInstanceOf(JsonWebKeyset.class)
			.hasName(jwsDefinition.getName())
			.hasPurpose(jwsDefinition.getPurpose())
			.createdByFactory(JoseKeysetFactory.NAME)
			.hasKeyEncryptionKey(kek)
			.hasRotationInterval(jwsDefinition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(jwsDefinition.getDestructionGracePeriod().orElse(null))
			.assertThatKeys()
			.isNotNull()
			.hasSize(1)
			.extracting(Key::getAlgorithm, Key::getStatus, Key::isPrimary)
			.containsExactly(tuple(JoseAlgorithm.PS256, KeyStatus.ENABLED, true));
	}

	@Test
	@Order(3)
	@DisplayName("should generate keyset using supported JOSE encryption algorithm")
	void shouldGenerateEncryptingKeyset() {
		final var kek = store.kek(KEK_PROVIDER, KEK_IDENTIFIER);

		KeysetAssert.assertThat(store.create(kek, jweDefinition))
			.isInstanceOf(JsonWebKeyset.class)
			.hasName(jweDefinition.getName())
			.hasPurpose(jweDefinition.getPurpose())
			.createdByFactory(JoseKeysetFactory.NAME)
			.hasKeyEncryptionKey(kek)
			.hasRotationInterval(jweDefinition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(jweDefinition.getDestructionGracePeriod().orElse(null))
			.assertThatKeys()
			.isNotNull()
			.hasSize(1)
			.extracting(Key::getAlgorithm, Key::getStatus, Key::isPrimary)
			.containsExactly(tuple(JoseAlgorithm.A128KW, KeyStatus.ENABLED, true));
	}

	@Test
	@Order(3)
	@DisplayName("should wrap and write keyset in the repository")
	void shouldWriteKeyset() throws Exception {
		final var jwk = new OctetSequenceKeyGenerator(128)
			.keyID("test-id")
			.generate();

		final var primary = new JsonWebKey.Builder(jwk)
			.id("test-key")
			.algorithm(JoseAlgorithm.A128KW)
			.primary()
			.status(KeyStatus.ENABLED)
			.build();

		final var keyset = new JsonWebKeyset.Builder(List.of(primary))
			.name("simple-keyset")
			.purpose(JoseAlgorithm.A128KW.purpose())
			.keyEncryptionKey(store.kek(KEK_PROVIDER, KEK_IDENTIFIER))
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

		KeysetAssert.assertThat(store.read(jwsDefinition.getName()))
			.isInstanceOf(JsonWebKeyset.class)
			.hasName(jwsDefinition.getName())
			.hasPurpose(jwsDefinition.getPurpose())
			.createdByFactory(JoseKeysetFactory.NAME)
			.hasKeyEncryptionKey(kek)
			.hasRotationInterval(jwsDefinition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(jwsDefinition.getDestructionGracePeriod().orElse(null))
			.assertThatKeys()
			.isNotNull()
			.hasSize(1)
			.extracting(Key::getAlgorithm, Key::getStatus, Key::isPrimary)
			.containsExactly(tuple(JoseAlgorithm.PS256, KeyStatus.ENABLED, true));
	}

	@Test
	@Order(4)
	@DisplayName("should read and unwrap encryption keyset from the repository")
	void shouldReadEncryptingKeyset() {
		final var kek = store.kek(KEK_PROVIDER, KEK_IDENTIFIER);

		KeysetAssert.assertThat(store.read(jweDefinition.getName()))
			.isInstanceOf(JsonWebKeyset.class)
			.hasName(jweDefinition.getName())
			.hasPurpose(jweDefinition.getPurpose())
			.createdByFactory(JoseKeysetFactory.NAME)
			.hasKeyEncryptionKey(kek)
			.hasRotationInterval(jweDefinition.getRotationInterval().orElse(null))
			.hasDestructionGracePeriod(jweDefinition.getDestructionGracePeriod().orElse(null))
			.assertThatKeys()
			.isNotNull()
			.hasSize(1)
			.extracting(Key::getAlgorithm, Key::getStatus, Key::isPrimary)
			.containsExactly(tuple(JoseAlgorithm.A128KW, KeyStatus.ENABLED, true));
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
